//! Cryptographically attested delegation certificates for AI agent permissions.
//!
//! # The Problem
//!
//! When agent A delegates permissions to agent B, how does a third-party
//! verifier C confirm that B's permissions were legitimately derived from
//! A's authority? Traditional approaches require C to contact A (online
//! verification) or trust B's self-reported permissions (no verification).
//!
//! # The Solution: Biscuit-Style Signed Block Chain
//!
//! Each delegation produces a cryptographic certificate containing:
//!
//! 1. **Authority block**: root permissions signed by the root authority
//! 2. **Delegation blocks**: each records `meet(parent, requested)` with
//!    a [`MeetJustification`] constructive witness, signed by ephemeral Ed25519 keys
//! 3. **Hash chain**: SHA-256 links between blocks prevent reordering
//! 4. **Monotone re-verification**: `leq()` on the product lattice confirms attenuation
//!
//! Any verifier with the root authority's public key can verify the entire
//! chain offline in O(n·d) where n is chain depth and d is lattice dimensions.
//!
//! # Design Honesty
//!
//! This is **not** proof-carrying code in the Necula (1996) sense, where the
//! certificate contains a logical proof term checked by a small trusted kernel.
//! Instead, the verifier **re-executes** the lattice meet and checks `leq()` —
//! which is O(d) for d=12 dimensions, making re-execution cheaper than embedding
//! and checking a proof term. The [`MeetJustification`] is a *constructive witness*
//! that makes each delegation step auditable, not just verifiable.
//!
//! The honest framing: **cryptographically attested delegation with constructive
//! witnesses** — each hop carries a signed computation trace and per-dimension
//! restriction rationale.
//!
//! # Security Properties
//!
//! - **Unforgeable**: Ed25519 signatures prevent certificate fabrication
//! - **Tamper-evident**: SHA-256 hash chain detects reordering/modification
//! - **Monotone**: Each block's permissions are strictly ≤ parent's
//! - **Bounded**: Chain depth is limited (default: 10 hops)
//! - **Time-bounded**: Each block has an expiration ≤ parent's
//! - **Witness-carrying**: The [`MeetJustification`] provides per-dimension restriction rationale
//!
//! # Example
//!
//! ```rust
//! use portcullis::certificate::{LatticeCertificate, verify_certificate};
//! use portcullis::PermissionLattice;
//! use ring::signature::KeyPair;
//! use chrono::{Utc, Duration};
//!
//! // Root authority generates a key pair
//! let rng = ring::rand::SystemRandom::new();
//! let root_pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
//! let root_key = ring::signature::Ed25519KeyPair::from_pkcs8(root_pkcs8.as_ref()).unwrap();
//!
//! // Mint a root certificate
//! let not_after = Utc::now() + Duration::hours(8);
//! let (cert, holder_key) = LatticeCertificate::mint(
//!     PermissionLattice::permissive(),
//!     "spiffe://nucleus.local/human/alice".into(),
//!     not_after,
//!     &root_key,
//!     &rng,
//! );
//!
//! // Delegate to a sub-agent
//! let requested = PermissionLattice::restrictive();
//! let (cert, _delegatee_key) = cert.delegate(
//!     &requested,
//!     "spiffe://nucleus.local/agent/coder-042".into(),
//!     not_after,
//!     &holder_key,
//!     &rng,
//! ).unwrap();
//!
//! // Any verifier can check the certificate
//! let root_pub = root_key.public_key().as_ref();
//! let verified = verify_certificate(&cert, root_pub, Utc::now(), 10).unwrap();
//! assert_eq!(verified.chain_depth(), 1);
//! ```

use chrono::{DateTime, Utc};
// `ring` (Ed25519 sign/verify) can't compile to WASM, so all ring usage is
// gated behind `crypto`; the certificate DATA types + non-crypto logic below
// stay always-compiled so the kernel can use them on every target.
#[cfg(feature = "crypto")]
use ring::rand::SecureRandom;
#[cfg(feature = "crypto")]
use ring::signature::{Ed25519KeyPair, KeyPair};
use sha2::{Digest, Sha256};
use std::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "crypto")]
use crate::delegation::meet_with_justification;
use crate::delegation::MeetJustification;
use crate::PermissionLattice;

/// Maximum chain depth (configurable at verification time, this is the default).
pub const DEFAULT_MAX_CHAIN_DEPTH: usize = 10;

// ═══════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════

/// The authority (root) block of a delegation certificate.
///
/// Establishes the root of trust: the initial permissions and the identity
/// of the root authority who signed them.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AuthorityBlock {
    /// Root permissions (the ceiling for all delegations).
    pub root_permissions: PermissionLattice,
    /// Identity of the root authority (e.g., SPIFFE ID).
    pub root_identity: String,
    /// Certificate expiration.
    pub not_after: DateTime<Utc>,
    /// Ed25519 signature over the canonical signing payload.
    pub signature: Vec<u8>,
    /// Public key for verifying the next block (or proof-of-possession if no delegations).
    pub next_key: Vec<u8>,
    /// Fingerprint of the certificate this authority was *re-rooted* from.
    ///
    /// When an issuer mints a fresh root on behalf of a caller who proved its
    /// own chain (the caller's leaf identity becomes this block's
    /// `root_identity`, and `root_permissions` is the caller's effective
    /// lattice narrowed by the request), this records which chain that was —
    /// token-exchange semantics, the `act` claim of RFC 8693. `None` for a
    /// genuine root. Signature-covered via [`signing_payload`](Self::signing_payload).
    #[cfg_attr(feature = "serde", serde(default))]
    pub provenance: Option<[u8; 32]>,
}

/// A delegation block recording one hop in the permission chain.
///
/// Each block contains the result of `meet(parent, requested)` along with
/// the constructive witness ([`MeetJustification`]) proving that permissions
/// were correctly attenuated.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DelegationBlock {
    /// Effective permissions after the meet operation.
    pub effective_permissions: PermissionLattice,
    /// Constructive witness: which dimensions were restricted and why.
    pub justification: MeetJustification,
    /// Identity of the delegator.
    pub from_identity: String,
    /// Identity of the delegatee.
    pub to_identity: String,
    /// Block expiration (must be ≤ parent block's not_after).
    pub not_after: DateTime<Utc>,
    /// Sink scope — restricts WHERE delegated operations can target (#594).
    /// Monotone: child scope ⊆ parent scope.
    #[cfg_attr(feature = "serde", serde(default))]
    pub sink_scope: SinkScope,
    /// SHA-256 hash of the previous block (tamper-evident ordering).
    pub prev_block_hash: Vec<u8>,
    /// Ed25519 signature by the previous holder's ephemeral key.
    pub signature: Vec<u8>,
    /// Public key for verifying the next block.
    pub next_key: Vec<u8>,
}

/// A cryptographically attested delegation certificate.
///
/// Contains a signed chain of delegation blocks with constructive witnesses,
/// forming a machine-checkable attestation that the holder's permissions were
/// legitimately derived from the root authority through monotone lattice meets.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct LatticeCertificate {
    authority: AuthorityBlock,
    blocks: Vec<DelegationBlock>,
    /// Proof-of-possession: signature by the final holder's ephemeral key
    /// over the certificate's proof-of-possession payload.
    final_signature: Vec<u8>,
}

/// Marker type that makes [`VerifiedPermissions`] unforgeable outside this
/// module — see the struct's own doc comment. Named distinctly from other
/// sealed types in this codebase (`nucleus_ifc_kernel::discharge::Seal`,
/// `nucleus_tool_proxy::session_token`'s own marker) since each lives in a
/// different crate; there is no shared "the" seal type.
#[derive(Clone)]
struct CertificateSeal;

/// Result of successful certificate verification.
///
/// Sealed (#2450): every field is private, the only constructor
/// ([`Self::new`]) is private to this module, and the `_seal` field holds a
/// [`CertificateSeal`] that cannot be named outside it — so no
/// `VerifiedPermissions` struct literal compiles in another crate, even one
/// naming all five public-looking fields (see the `compile_fail` doctest
/// below). Only [`verify_certificate`] produces one, guaranteeing that the
/// permissions were cryptographically verified. Same pattern as
/// `nucleus_ifc_kernel::discharge::DischargedBundle`.
///
/// ```compile_fail
/// // This code does NOT compile — CertificateSeal is not accessible, and
/// // the fields are private even ignoring that.
/// use portcullis::certificate::VerifiedPermissions;
/// use portcullis::PermissionLattice;
/// let verified = VerifiedPermissions {
///     effective: PermissionLattice::restrictive(),
///     chain_depth: 0,
///     root_identity: "spiffe://attacker/forged".to_string(),
///     leaf_identity: "spiffe://attacker/forged".to_string(),
///     sink_scope: Default::default(),
///     // no `_seal`: the field is private, and CertificateSeal is
///     // unnameable outside this module regardless.
/// };
/// ```
#[derive(Clone)]
pub struct VerifiedPermissions {
    effective: PermissionLattice,
    chain_depth: usize,
    root_identity: String,
    leaf_identity: String,
    sink_scope: SinkScope,
    _seal: CertificateSeal,
}

impl VerifiedPermissions {
    /// Private constructor — only callable from within this module (the
    /// verifier, and this module's own tests). Gated behind `crypto`, same as
    /// its one caller ([`verify_certificate`]): without that feature `new` is
    /// genuinely unreachable, and leaving it ungated produces a dead-code
    /// warning in any crate that depends on `portcullis` with
    /// `default-features = false` and no other path to `crypto`.
    #[cfg(feature = "crypto")]
    fn new(
        effective: PermissionLattice,
        chain_depth: usize,
        root_identity: String,
        leaf_identity: String,
        sink_scope: SinkScope,
    ) -> Self {
        Self {
            effective,
            chain_depth,
            root_identity,
            leaf_identity,
            sink_scope,
            _seal: CertificateSeal,
        }
    }

    /// The effective permissions at the end of the chain.
    pub fn effective(&self) -> &PermissionLattice {
        &self.effective
    }

    /// Number of delegation hops from root to leaf.
    pub fn chain_depth(&self) -> usize {
        self.chain_depth
    }

    /// Identity of the root authority.
    pub fn root_identity(&self) -> &str {
        &self.root_identity
    }

    /// Identity of the leaf holder.
    pub fn leaf_identity(&self) -> &str {
        &self.leaf_identity
    }

    /// Effective sink scope at the end of the chain (#594).
    pub fn sink_scope(&self) -> &SinkScope {
        &self.sink_scope
    }
}

impl fmt::Debug for VerifiedPermissions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedPermissions")
            .field("chain_depth", &self.chain_depth)
            .field("root_identity", &self.root_identity)
            .field("leaf_identity", &self.leaf_identity)
            .finish()
    }
}

/// Errors during certificate verification.
#[derive(Debug, Clone)]
pub enum CertificateError {
    /// Ed25519 signature verification failed at the specified block.
    InvalidSignature {
        /// 0 = authority block, 1+ = delegation blocks.
        block_index: usize,
    },
    /// SHA-256 hash chain linkage is broken.
    BrokenHashChain {
        /// Index of the block with the broken link.
        block_index: usize,
    },
    /// A delegation block has permissions exceeding its parent (amplification attack).
    MonotoneViolation {
        /// Index of the violating block.
        block_index: usize,
    },
    /// A block has expired.
    Expired {
        /// Index of the expired block.
        block_index: usize,
    },
    /// The delegation chain exceeds the maximum allowed depth.
    ChainTooDeep {
        /// Actual chain depth.
        depth: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// The final proof-of-possession signature is invalid.
    InvalidProofOfPossession,
    /// A delegation block's sink scope exceeds its parent's scope (#594).
    SinkScopeViolation {
        /// Index of the violating block.
        block_index: usize,
    },
}

impl fmt::Display for CertificateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSignature { block_index } => {
                write!(f, "Invalid signature at block {}", block_index)
            }
            Self::BrokenHashChain { block_index } => {
                write!(f, "Broken hash chain at block {}", block_index)
            }
            Self::MonotoneViolation { block_index } => {
                write!(
                    f,
                    "Monotone violation (permission amplification) at block {}",
                    block_index
                )
            }
            Self::Expired { block_index } => {
                write!(f, "Block {} has expired", block_index)
            }
            Self::ChainTooDeep { depth, max } => {
                write!(f, "Chain depth {} exceeds maximum {}", depth, max)
            }
            Self::InvalidProofOfPossession => {
                write!(f, "Invalid proof-of-possession signature")
            }
            Self::SinkScopeViolation { block_index } => {
                write!(
                    f,
                    "Sink scope violation (scope widening) at block {}",
                    block_index
                )
            }
        }
    }
}

impl std::error::Error for CertificateError {}

/// Errors during certificate delegation.
#[derive(Debug, Clone)]
pub enum CertificateDelegationError {
    /// The caller's key doesn't match the expected next_key.
    KeyMismatch,
    /// The requested expiry exceeds the parent's expiry.
    ExpiryExceedsParent,
    /// The chain would exceed the maximum allowed depth.
    ChainTooDeep {
        /// Current chain depth.
        depth: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// Ed25519 key generation failed.
    KeyGenerationFailed,
    /// The requested sink scope exceeds the parent's scope (#594).
    SinkScopeExceedsParent,
}

impl fmt::Display for CertificateDelegationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyMismatch => write!(f, "Caller's key does not match expected next_key"),
            Self::ExpiryExceedsParent => write!(f, "Requested expiry exceeds parent block"),
            Self::ChainTooDeep { depth, max } => {
                write!(f, "Chain depth {} would exceed maximum {}", depth, max)
            }
            Self::KeyGenerationFailed => write!(f, "Ed25519 key generation failed"),
            Self::SinkScopeExceedsParent => {
                write!(f, "Requested sink scope exceeds parent's scope")
            }
        }
    }
}

impl std::error::Error for CertificateDelegationError {}

/// Errors from [`LatticeCertificate::mint_child`] — either layer it
/// validates can refuse the mint. See that function's own doc comment for
/// why both layers exist.
#[derive(Debug, Clone)]
pub enum CertificateMintChildError {
    /// The lattice-level check ([`crate::PermissionLattice::delegate_to`])
    /// refused: insufficient budget, or the parent lattice's own time
    /// window has already expired.
    Lattice(crate::DelegationError),
    /// The certificate-chain-level check ([`LatticeCertificate::delegate`])
    /// refused: chain depth, certificate-block expiry, key mismatch, or
    /// sink scope.
    Chain(CertificateDelegationError),
}

impl fmt::Display for CertificateMintChildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lattice(e) => write!(f, "lattice-level check refused mint_child: {e}"),
            Self::Chain(e) => write!(f, "certificate-chain check refused mint_child: {e}"),
        }
    }
}

impl std::error::Error for CertificateMintChildError {}

// ═══════════════════════════════════════════════════════════════════════════
// SINK SCOPE — restricts WHERE delegated operations can target (#594)
// ═══════════════════════════════════════════════════════════════════════════

/// Restricts which sinks a delegated agent can target.
///
/// An empty `Vec` means "unrestricted" (all sinks allowed for that dimension).
/// When non-empty, only matching targets are permitted. Delegation must be
/// monotone: child scope ⊆ parent scope (a child cannot widen access).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SinkScope {
    /// Allowed file path prefixes (e.g., "/workspace/output/").
    /// Empty = all paths allowed by the capability lattice.
    #[cfg_attr(feature = "serde", serde(default))]
    pub allowed_paths: Vec<String>,
    /// Allowed network hosts (e.g., "api.example.com").
    /// Empty = all hosts allowed.
    #[cfg_attr(feature = "serde", serde(default))]
    pub allowed_hosts: Vec<String>,
    /// Allowed git ref patterns (e.g., "origin/feature-*").
    /// Empty = all refs allowed.
    #[cfg_attr(feature = "serde", serde(default))]
    pub allowed_git_refs: Vec<String>,
}

impl SinkScope {
    /// Unrestricted scope — allows all targets.
    pub fn unrestricted() -> Self {
        Self::default()
    }

    /// Check if `child` is a subset of `self` (monotone attenuation).
    ///
    /// Rules:
    /// - If parent is unrestricted (empty), child can be anything (including restricted)
    /// - If parent is restricted, child must be a subset (every child entry must match a parent entry)
    /// - An empty child vec inherits the parent's restrictions
    pub fn contains(&self, child: &SinkScope) -> bool {
        subset_check(&self.allowed_paths, &child.allowed_paths)
            && subset_check(&self.allowed_hosts, &child.allowed_hosts)
            && subset_check(&self.allowed_git_refs, &child.allowed_git_refs)
    }
}

/// Check if `child_list` ⊆ `parent_list`.
/// An empty parent means unrestricted (any child is allowed).
/// A non-empty parent requires every child entry to be present in the parent.
/// An empty child inherits (is considered within) the parent scope.
fn subset_check(parent: &[String], child: &[String]) -> bool {
    if parent.is_empty() {
        // Parent unrestricted — any child restriction is fine
        return true;
    }
    if child.is_empty() {
        // Child unrestricted but parent is restricted — NOT a subset
        // A child with no restrictions would be wider than the parent
        return false;
    }
    // Every child entry must exist in parent
    child.iter().all(|c| parent.iter().any(|p| p == c))
}

// ═══════════════════════════════════════════════════════════════════════════
// CANONICAL HASHING
// ═══════════════════════════════════════════════════════════════════════════

/// Compute a canonical hash of the security-relevant fields of a PermissionLattice.
///
/// This intentionally excludes metadata (id, description, created_at, created_by,
/// derived_from) to produce deterministic hashes for structurally identical permissions.
pub fn canonical_permissions_hash(perms: &PermissionLattice) -> Vec<u8> {
    let mut hasher = Sha256::new();

    // Capabilities (13 named dimensions, each as u8, then the extension map).
    //
    // `spawn_agent` and `extensions` were outside this digest until the
    // certificate convergence work: they rode inside the signed *struct* but
    // outside the signed *bytes*, so anyone who could edit the serialized JSON
    // could raise them on every block without invalidating a single Ed25519
    // signature — and `verify_certificate`'s monotone check compared the same
    // tampered values. `spawn_agent` is precisely the dimension that gates
    // sub-pod creation, so that hole sat on the authority this certificate
    // exists to attest. Pinned by `spawn_agent_is_signature_covered`.
    hasher.update([perms.capabilities.read_files as u8]);
    hasher.update([perms.capabilities.write_files as u8]);
    hasher.update([perms.capabilities.edit_files as u8]);
    hasher.update([perms.capabilities.run_bash as u8]);
    hasher.update([perms.capabilities.glob_search as u8]);
    hasher.update([perms.capabilities.grep_search as u8]);
    hasher.update([perms.capabilities.web_search as u8]);
    hasher.update([perms.capabilities.web_fetch as u8]);
    hasher.update([perms.capabilities.git_commit as u8]);
    hasher.update([perms.capabilities.git_push as u8]);
    hasher.update([perms.capabilities.create_pr as u8]);
    hasher.update([perms.capabilities.manage_pods as u8]);
    hasher.update([perms.capabilities.spawn_agent as u8]);
    #[cfg(not(kani))]
    {
        // BTreeMap iterates in key order, so this is deterministic.
        hasher.update((perms.capabilities.extensions.len() as u32).to_le_bytes());
        for (op, level) in &perms.capabilities.extensions {
            hasher.update(op.0.as_bytes());
            hasher.update([0]);
            hasher.update([*level as u8]);
        }
    }

    // Obligations (sorted set of operation indices for determinism)
    let mut ops: Vec<u8> = perms
        .obligations
        .approvals
        .iter()
        .map(|op| *op as u8)
        .collect();
    ops.sort();
    hasher.update([ops.len() as u8]);
    hasher.update(&ops);

    // Paths (sorted for determinism)
    let mut allowed_paths: Vec<&str> = perms.paths.allowed.iter().map(|s| s.as_str()).collect();
    allowed_paths.sort();
    hasher.update((allowed_paths.len() as u32).to_le_bytes());
    for p in &allowed_paths {
        hasher.update(p.as_bytes());
        hasher.update([0]); // null separator
    }
    let mut blocked_paths: Vec<&str> = perms.paths.blocked.iter().map(|s| s.as_str()).collect();
    blocked_paths.sort();
    hasher.update((blocked_paths.len() as u32).to_le_bytes());
    for p in &blocked_paths {
        hasher.update(p.as_bytes());
        hasher.update([0]);
    }
    if let Some(ref wd) = perms.paths.work_dir {
        hasher.update([1]);
        hasher.update(wd.to_string_lossy().as_bytes());
    } else {
        hasher.update([0]);
    }

    // Budget. `consumed_usd` is signature-covered too: a chain hop that
    // carries budget forward carries what has already been spent against
    // it, and an unsigned `consumed_usd` would let a holder reset it to zero.
    hasher.update(perms.budget.max_cost_usd.to_string().as_bytes());
    hasher.update([0]);
    hasher.update(perms.budget.consumed_usd.to_string().as_bytes());
    hasher.update([0]);
    hasher.update(perms.budget.max_input_tokens.to_le_bytes());
    hasher.update(perms.budget.max_output_tokens.to_le_bytes());

    // Commands (sorted for determinism)
    let mut allowed_cmds: Vec<&str> = perms.commands.allowed.iter().map(|s| s.as_str()).collect();
    allowed_cmds.sort();
    hasher.update((allowed_cmds.len() as u32).to_le_bytes());
    for c in &allowed_cmds {
        hasher.update(c.as_bytes());
        hasher.update([0]);
    }
    let mut blocked_cmds: Vec<&str> = perms.commands.blocked.iter().map(|s| s.as_str()).collect();
    blocked_cmds.sort();
    hasher.update((blocked_cmds.len() as u32).to_le_bytes());
    for c in &blocked_cmds {
        hasher.update(c.as_bytes());
        hasher.update([0]);
    }

    // Time bounds
    hasher.update(perms.time.valid_from.timestamp().to_le_bytes());
    hasher.update(perms.time.valid_until.timestamp().to_le_bytes());

    //  UninhabitableState constraint
    hasher.update([perms.uninhabitable_constraint as u8]);

    hasher.finalize().to_vec()
}

impl AuthorityBlock {
    /// Compute the canonical payload for signing.
    #[cfg(feature = "crypto")]
    pub(crate) fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        // v2: canonical hash now covers spawn_agent/extensions/consumed_usd,
        // and the payload carries `provenance`. Tokens issued under v1 do not
        // verify — none exist outside this tree.
        payload.extend_from_slice(b"lattice-cert-authority-v2:");
        payload.extend_from_slice(self.root_identity.as_bytes());
        payload.push(0); // separator
        payload.extend_from_slice(&self.not_after.timestamp().to_le_bytes());
        payload.extend_from_slice(&canonical_permissions_hash(&self.root_permissions));
        payload.extend_from_slice(&self.next_key);
        match self.provenance {
            Some(fp) => {
                payload.push(1);
                payload.extend_from_slice(&fp);
            }
            None => payload.push(0),
        }
        payload
    }

    /// Compute the SHA-256 hash of this block (including the signature).
    #[cfg(feature = "crypto")]
    fn block_hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(self.signing_payload());
        hasher.update(&self.signature);
        hasher.finalize().to_vec()
    }
}

impl DelegationBlock {
    /// Compute the canonical payload for signing.
    #[cfg(feature = "crypto")]
    pub(crate) fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        // v3: canonical hash now covers spawn_agent/extensions/consumed_usd.
        payload.extend_from_slice(b"lattice-cert-delegation-v3:");
        payload.extend_from_slice(self.from_identity.as_bytes());
        payload.push(0);
        payload.extend_from_slice(self.to_identity.as_bytes());
        payload.push(0);
        payload.extend_from_slice(&self.not_after.timestamp().to_le_bytes());
        payload.extend_from_slice(&canonical_permissions_hash(&self.effective_permissions));
        // Sink scope is included in the signed payload (#594)
        // so tampering with scope invalidates the signature.
        for p in &self.sink_scope.allowed_paths {
            payload.extend_from_slice(b"path:");
            payload.extend_from_slice(p.as_bytes());
            payload.push(0);
        }
        for h in &self.sink_scope.allowed_hosts {
            payload.extend_from_slice(b"host:");
            payload.extend_from_slice(h.as_bytes());
            payload.push(0);
        }
        for r in &self.sink_scope.allowed_git_refs {
            payload.extend_from_slice(b"ref:");
            payload.extend_from_slice(r.as_bytes());
            payload.push(0);
        }
        payload.extend_from_slice(&self.prev_block_hash);
        payload.extend_from_slice(&self.next_key);
        payload
    }

    /// Compute the SHA-256 hash of this block (including the signature).
    #[cfg(feature = "crypto")]
    fn block_hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(self.signing_payload());
        hasher.update(&self.signature);
        hasher.finalize().to_vec()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CERTIFICATE OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════

impl LatticeCertificate {
    /// Mint a new root authority certificate.
    ///
    /// This creates the root of a delegation chain. The returned `Ed25519KeyPair`
    /// is the ephemeral key that the root authority holds — it must be passed to
    /// `delegate()` when delegating to the first sub-agent.
    ///
    /// # Arguments
    ///
    /// * `root_permissions` — The ceiling permissions for all delegations.
    /// * `root_identity` — SPIFFE ID or other identity of the root authority.
    /// * `not_after` — Certificate expiration.
    /// * `signing_key` — The root authority's long-term Ed25519 signing key.
    /// * `rng` — Secure random number generator for ephemeral key generation.
    #[cfg(feature = "crypto")]
    pub fn mint(
        root_permissions: PermissionLattice,
        root_identity: String,
        not_after: DateTime<Utc>,
        signing_key: &Ed25519KeyPair,
        rng: &dyn SecureRandom,
    ) -> (Self, Ed25519KeyPair) {
        // Generate ephemeral key pair for the holder
        let holder_pkcs8 =
            Ed25519KeyPair::generate_pkcs8(rng).expect("Ed25519 key generation failed");
        let holder_key =
            Ed25519KeyPair::from_pkcs8(holder_pkcs8.as_ref()).expect("Ed25519 key parse failed");

        let cert = Self::mint_with_holder_key(
            root_permissions,
            root_identity,
            not_after,
            None,
            signing_key,
            &holder_key,
        );

        (cert, holder_key)
    }

    /// Mint a root authority certificate whose holder key the CALLER owns.
    ///
    /// [`Self::mint`] generates the holder key internally and hands back only
    /// the `ring` keypair, which cannot export its seed — so nothing minted
    /// that way can persist its holder key across a restart or hand it to
    /// another process. An issuer that must keep `(certificate, holder key)`
    /// per pod (the node's per-pod authority registry) generates the PKCS#8
    /// document itself, keeps it, and mints through this constructor.
    ///
    /// `provenance` records the fingerprint of the chain this root was
    /// re-rooted from (see [`AuthorityBlock::provenance`]); pass `None` for a
    /// genuine root.
    #[cfg(feature = "crypto")]
    pub fn mint_with_holder_key(
        root_permissions: PermissionLattice,
        root_identity: String,
        not_after: DateTime<Utc>,
        provenance: Option<[u8; 32]>,
        signing_key: &Ed25519KeyPair,
        holder_key: &Ed25519KeyPair,
    ) -> Self {
        let next_key = holder_key.public_key().as_ref().to_vec();

        // Build authority block (without signature initially)
        let mut authority = AuthorityBlock {
            root_permissions,
            root_identity,
            not_after,
            signature: Vec::new(),
            next_key,
            provenance,
        };

        // Sign the canonical payload
        let payload = authority.signing_payload();
        authority.signature = signing_key.sign(&payload).as_ref().to_vec();

        // Build proof-of-possession with the holder key
        let pop_payload = Self::pop_payload_for_block_hash(&authority.block_hash());
        let final_signature = holder_key.sign(&pop_payload).as_ref().to_vec();

        Self {
            authority,
            blocks: Vec::new(),
            final_signature,
        }
    }

    /// Delegate permissions to a sub-agent, producing a new certificate.
    ///
    /// Computes `meet(parent_permissions, requested)` and appends a new
    /// delegation block with the [`MeetJustification`] as the constructive witness.
    ///
    /// Returns the extended certificate and a new ephemeral `Ed25519KeyPair`
    /// for the delegatee to use when delegating further.
    ///
    /// # Errors
    ///
    /// - [`CertificateDelegationError::KeyMismatch`] if `current_holder_key` doesn't
    ///   match the expected next key.
    /// - [`CertificateDelegationError::ExpiryExceedsParent`] if `not_after` exceeds
    ///   the parent block's expiry.
    /// - [`CertificateDelegationError::ChainTooDeep`] if the chain would exceed
    ///   [`DEFAULT_MAX_CHAIN_DEPTH`].
    #[cfg(feature = "crypto")]
    pub fn delegate(
        &self,
        requested: &PermissionLattice,
        to_identity: String,
        not_after: DateTime<Utc>,
        current_holder_key: &Ed25519KeyPair,
        rng: &dyn SecureRandom,
    ) -> Result<(Self, Ed25519KeyPair), CertificateDelegationError> {
        self.delegate_with_scope(
            requested,
            to_identity,
            not_after,
            SinkScope::unrestricted(),
            current_holder_key,
            rng,
        )
    }

    /// Delegate with explicit sink scope restrictions (#594).
    ///
    /// The `sink_scope` must be a subset of the parent's scope (monotone).
    /// An unrestricted parent allows any child scope; a restricted parent
    /// requires the child to be equally or more restricted.
    #[cfg(feature = "crypto")]
    pub fn delegate_with_scope(
        &self,
        requested: &PermissionLattice,
        to_identity: String,
        not_after: DateTime<Utc>,
        sink_scope: SinkScope,
        current_holder_key: &Ed25519KeyPair,
        rng: &dyn SecureRandom,
    ) -> Result<(Self, Ed25519KeyPair), CertificateDelegationError> {
        // Generate ephemeral key pair for the delegatee
        let delegatee_pkcs8 = Ed25519KeyPair::generate_pkcs8(rng)
            .map_err(|_| CertificateDelegationError::KeyGenerationFailed)?;
        let delegatee_key = Ed25519KeyPair::from_pkcs8(delegatee_pkcs8.as_ref())
            .map_err(|_| CertificateDelegationError::KeyGenerationFailed)?;

        let cert = self.delegate_with_scope_using_key(
            requested,
            to_identity,
            not_after,
            sink_scope,
            current_holder_key,
            &delegatee_key,
        )?;
        Ok((cert, delegatee_key))
    }

    /// [`Self::delegate_with_scope`] where the CALLER owns the delegatee's
    /// holder key.
    ///
    /// The `rng` variants generate the delegatee key internally and return
    /// only the `ring` keypair, which cannot export its seed — so the caller
    /// can never persist it. An issuer that has to keep the delegatee's key
    /// (to delegate again on that holder's behalf later, after a restart)
    /// generates the PKCS#8 document itself, keeps it, and delegates through
    /// this variant with the parsed keypair.
    #[cfg(feature = "crypto")]
    pub fn delegate_with_scope_using_key(
        &self,
        requested: &PermissionLattice,
        to_identity: String,
        not_after: DateTime<Utc>,
        sink_scope: SinkScope,
        current_holder_key: &Ed25519KeyPair,
        delegatee_key: &Ed25519KeyPair,
    ) -> Result<Self, CertificateDelegationError> {
        // Check chain depth
        if self.blocks.len() >= DEFAULT_MAX_CHAIN_DEPTH {
            return Err(CertificateDelegationError::ChainTooDeep {
                depth: self.blocks.len() + 1,
                max: DEFAULT_MAX_CHAIN_DEPTH,
            });
        }

        // Get parent context
        let (parent_permissions, parent_not_after, expected_next_key, prev_hash) =
            if self.blocks.is_empty() {
                (
                    &self.authority.root_permissions,
                    self.authority.not_after,
                    &self.authority.next_key,
                    self.authority.block_hash(),
                )
            } else {
                let last = self.blocks.last().unwrap();
                (
                    &last.effective_permissions,
                    last.not_after,
                    &last.next_key,
                    last.block_hash(),
                )
            };

        // Verify key matches
        if current_holder_key.public_key().as_ref() != expected_next_key.as_slice() {
            return Err(CertificateDelegationError::KeyMismatch);
        }

        // Check expiry
        if not_after > parent_not_after {
            return Err(CertificateDelegationError::ExpiryExceedsParent);
        }

        // Check sink scope monotonicity (#594)
        let parent_scope = if self.blocks.is_empty() {
            SinkScope::unrestricted() // Root has unrestricted scope
        } else {
            self.blocks.last().unwrap().sink_scope.clone()
        };
        if !parent_scope.contains(&sink_scope) {
            return Err(CertificateDelegationError::SinkScopeExceedsParent);
        }

        // Compute the meet with justification (the constructive witness)
        let (effective_permissions, justification) =
            meet_with_justification(parent_permissions, requested);

        // Get from_identity
        let from_identity = if self.blocks.is_empty() {
            self.authority.root_identity.clone()
        } else {
            self.blocks.last().unwrap().to_identity.clone()
        };

        let next_key = delegatee_key.public_key().as_ref().to_vec();

        // Build delegation block
        let mut block = DelegationBlock {
            effective_permissions,
            justification,
            from_identity,
            to_identity,
            not_after,
            sink_scope,
            prev_block_hash: prev_hash,
            signature: Vec::new(),
            next_key,
        };

        // Sign with the current holder's key
        let payload = block.signing_payload();
        block.signature = current_holder_key.sign(&payload).as_ref().to_vec();

        // Build new certificate
        let mut new_blocks = self.blocks.clone();
        new_blocks.push(block);

        // New proof-of-possession with delegatee key
        let last_hash = new_blocks.last().unwrap().block_hash();
        let pop_payload = Self::pop_payload_for_block_hash(&last_hash);
        let final_signature = delegatee_key.sign(&pop_payload).as_ref().to_vec();

        Ok(Self {
            authority: self.authority.clone(),
            blocks: new_blocks,
            final_signature,
        })
    }

    /// Mint a child certificate, validated at BOTH layers: the lattice's own
    /// budget/expiry (via [`PermissionLattice::delegate_to`]) and the
    /// certificate chain's own depth/expiry/key/scope checks (via
    /// [`Self::delegate_with_scope`]).
    ///
    /// # Why this exists (#2432)
    ///
    /// [`Self::delegate`]/[`Self::delegate_with_scope`] compute the child's
    /// permissions via [`meet_with_justification`] — the raw lattice meet
    /// plus a constructive witness — which narrows every dimension but
    /// never *rejects*: a request for more budget than the parent has
    /// remaining, or against an already-expired parent lattice, silently
    /// clamps to whatever the meet produces instead of erring.
    /// [`PermissionLattice::delegate_to`] already has that validation
    /// ([`DelegationError::InsufficientBudget`], [`DelegationError::ParentExpired`])
    /// but nothing wired it into certificate minting — every spawn call site
    /// that hand-rolled chain construction inherited the gap. `mint_child` is
    /// the single choke point that closes it: call `delegate_to` first (so a
    /// request the lattice itself would refuse never reaches the chain at
    /// all), then delegate through the chain exactly as before.
    ///
    /// `delegate_to`'s own validated result is intentionally NOT what gets
    /// stored in the certificate block — `delegate_with_scope` recomputes
    /// the meet via `meet_with_justification` for its constructive witness,
    /// and the two are the same pure computation over the same inputs, so
    /// this costs a redundant (cheap, non-crypto) meet, not a second
    /// decision that could disagree with the first.
    ///
    /// # Errors
    ///
    /// [`CertificateMintChildError::Lattice`] wraps a [`DelegationError`] from
    /// the budget/expiry check; [`CertificateMintChildError::Chain`] wraps a
    /// [`CertificateDelegationError`] from the existing chain-level checks
    /// (depth, cert-block expiry, key match, sink scope — always
    /// unrestricted here, matching [`Self::delegate`]'s default).
    #[cfg(feature = "crypto")]
    pub fn mint_child(
        &self,
        requested: &PermissionLattice,
        child_identity: String,
        not_after: DateTime<Utc>,
        reason: &str,
        current_holder_key: &Ed25519KeyPair,
        rng: &dyn SecureRandom,
    ) -> Result<(Self, Ed25519KeyPair), CertificateMintChildError> {
        self.mint_child_with_scope(
            requested,
            child_identity,
            not_after,
            reason,
            SinkScope::unrestricted(),
            current_holder_key,
            rng,
        )
    }

    /// [`Self::mint_child`] with an explicit sink scope (the child's scope
    /// must be ⊆ the parent's, exactly as in [`Self::delegate_with_scope`]).
    #[cfg(feature = "crypto")]
    #[allow(clippy::too_many_arguments)]
    pub fn mint_child_with_scope(
        &self,
        requested: &PermissionLattice,
        child_identity: String,
        not_after: DateTime<Utc>,
        reason: &str,
        sink_scope: SinkScope,
        current_holder_key: &Ed25519KeyPair,
        rng: &dyn SecureRandom,
    ) -> Result<(Self, Ed25519KeyPair), CertificateMintChildError> {
        self.effective_permissions()
            .delegate_to(requested, reason)
            .map_err(CertificateMintChildError::Lattice)?;
        self.delegate_with_scope(
            requested,
            child_identity,
            not_after,
            sink_scope,
            current_holder_key,
            rng,
        )
        .map_err(CertificateMintChildError::Chain)
    }

    /// [`Self::mint_child_with_scope`] where the CALLER owns the child's
    /// holder key — the issuer-side constructor, for the same reason as
    /// [`Self::mint_with_holder_key`]: `ring` keypairs cannot export their
    /// seed, so an issuer that must persist the child's holder key generates
    /// the PKCS#8 document itself and passes the parsed keypair in.
    #[cfg(feature = "crypto")]
    #[allow(clippy::too_many_arguments)]
    pub fn mint_child_with_scope_using_key(
        &self,
        requested: &PermissionLattice,
        child_identity: String,
        not_after: DateTime<Utc>,
        reason: &str,
        sink_scope: SinkScope,
        current_holder_key: &Ed25519KeyPair,
        child_key: &Ed25519KeyPair,
    ) -> Result<Self, CertificateMintChildError> {
        self.effective_permissions()
            .delegate_to(requested, reason)
            .map_err(CertificateMintChildError::Lattice)?;
        self.delegate_with_scope_using_key(
            requested,
            child_identity,
            not_after,
            sink_scope,
            current_holder_key,
            child_key,
        )
        .map_err(CertificateMintChildError::Chain)
    }

    /// The effective permissions at the end of the chain.
    pub fn effective_permissions(&self) -> &PermissionLattice {
        self.blocks
            .last()
            .map(|b| &b.effective_permissions)
            .unwrap_or(&self.authority.root_permissions)
    }

    /// The depth of the delegation chain (number of hops from root to leaf).
    pub fn chain_depth(&self) -> usize {
        self.blocks.len()
    }

    /// The root identity.
    pub fn root_identity(&self) -> &str {
        &self.authority.root_identity
    }

    /// The leaf identity (the current holder).
    pub fn leaf_identity(&self) -> &str {
        self.blocks
            .last()
            .map(|b| b.to_identity.as_str())
            .unwrap_or(&self.authority.root_identity)
    }

    /// The authority block.
    pub fn authority(&self) -> &AuthorityBlock {
        &self.authority
    }

    /// The delegation blocks.
    pub fn delegation_blocks(&self) -> &[DelegationBlock] {
        &self.blocks
    }

    /// Compute the proof-of-possession payload from a block hash.
    #[cfg(feature = "crypto")]
    fn pop_payload_for_block_hash(block_hash: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"lattice-cert-pop-v1:");
        payload.extend_from_slice(block_hash);
        payload
    }

    /// Serialize to bytes (requires `serde` feature).
    #[cfg(feature = "serde")]
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialize from bytes (requires `serde` feature).
    #[cfg(feature = "serde")]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Compute the SHA-256 fingerprint of this certificate's canonical form.
    ///
    /// The fingerprint covers:
    /// 1. Authority block: root_identity + root_permissions canonical hash + not_after + signature
    /// 2. Each delegation block: identities + effective_permissions + not_after + hash chain + signature
    /// 3. The final proof-of-possession signature
    ///
    /// This fingerprint can be embedded in an X.509 extension (OID 1.3.6.1.4.1.57212.1.2)
    /// to cryptographically bind a SPIFFE identity to its lattice permissions.
    ///
    /// # Stability
    ///
    /// The fingerprint is deterministic for structurally identical certificates.
    /// Metadata fields (id, description, created_at) are excluded via `canonical_permissions_hash`.
    /// Signatures are included, binding to a specific signing event.
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();

        // Domain separation to prevent cross-protocol confusion
        hasher.update(b"lattice-cert-fingerprint-v2:");

        // Authority block
        hasher.update(self.authority.root_identity.as_bytes());
        hasher.update([0]); // separator
        hasher.update(self.authority.not_after.timestamp().to_le_bytes());
        hasher.update(canonical_permissions_hash(&self.authority.root_permissions));
        match self.authority.provenance {
            Some(fp) => {
                hasher.update([1]);
                hasher.update(fp);
            }
            None => hasher.update([0]),
        }
        hasher.update(&self.authority.signature);

        // Delegation blocks
        hasher.update((self.blocks.len() as u32).to_le_bytes());
        for block in &self.blocks {
            hasher.update(block.from_identity.as_bytes());
            hasher.update([0]);
            hasher.update(block.to_identity.as_bytes());
            hasher.update([0]);
            hasher.update(block.not_after.timestamp().to_le_bytes());
            hasher.update(canonical_permissions_hash(&block.effective_permissions));
            hasher.update(&block.prev_block_hash);
            hasher.update(&block.signature);
        }

        // Final proof-of-possession
        hasher.update(&self.final_signature);

        let digest = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(&digest);
        result
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// VERIFICATION — THE REFERENCE MONITOR
// ═══════════════════════════════════════════════════════════════════════════

/// Ed25519 verify on the strict (RFC 8032, `s < ℓ`, no small-order keys)
/// semantics — `ed25519_dalek::verify_strict`, NOT `ring`'s cofactored
/// verify. Ring's verify accepts the small-order identity-key forgery (see
/// `small_order_root_key_forgery_rejected`), and this chain is the credential
/// the runtime's authority rests on. Unifies the cert chain with the rest of
/// the attest stack (`token_sign`, `receipt_sign`) and removes `ring` from the
/// verify TCB (SECURITY_TODO #16). Signing stays on `ring`.
#[cfg(feature = "crypto")]
pub(crate) fn verify_ed25519_strict(
    public_key: &[u8],
    message: &[u8],
    sig: &[u8],
) -> Result<(), ()> {
    let vk_bytes: [u8; 32] = public_key.try_into().map_err(|_| ())?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&vk_bytes).map_err(|_| ())?;
    let sig = ed25519_dalek::Signature::from_slice(sig).map_err(|_| ())?;
    vk.verify_strict(message, &sig).map_err(|_| ())
}

/// Verify an attested delegation certificate.
///
/// This is the reference monitor: it checks every cryptographic and algebraic
/// property of the certificate chain. On success, returns [`VerifiedPermissions`]
/// which is a sealed type that can only be produced by this function.
///
/// # Checks performed
///
/// 1. Chain depth ≤ `max_chain_depth`
/// 2. Authority block signature against `root_public_key`
/// 3. Authority block not expired
/// 4. For each delegation block:
///    a. SHA-256 hash chain linkage
///    b. Ed25519 signature by previous holder
///    c. Monotone attenuation: `block.effective_permissions.leq(parent_permissions)`
///    d. Expiry: `now ≤ block.not_after`
/// 5. Final proof-of-possession signature
///
/// # Arguments
///
/// * `cert` — The certificate to verify.
/// * `root_public_key` — The 32-byte Ed25519 public key of the root authority.
/// * `now` — Current time for expiry checks.
/// * `max_chain_depth` — Maximum allowed delegation hops.
#[cfg(feature = "crypto")]
pub fn verify_certificate(
    cert: &LatticeCertificate,
    root_public_key: &[u8],
    now: DateTime<Utc>,
    max_chain_depth: usize,
) -> Result<VerifiedPermissions, CertificateError> {
    // 1. Check chain depth
    if cert.blocks.len() > max_chain_depth {
        return Err(CertificateError::ChainTooDeep {
            depth: cert.blocks.len(),
            max: max_chain_depth,
        });
    }

    // 2. Verify authority block signature
    let authority_payload = cert.authority.signing_payload();
    verify_ed25519_strict(
        root_public_key,
        &authority_payload,
        &cert.authority.signature,
    )
    .map_err(|_| CertificateError::InvalidSignature { block_index: 0 })?;

    // 3. Check authority expiry
    if now > cert.authority.not_after {
        return Err(CertificateError::Expired { block_index: 0 });
    }

    // 4. Walk the delegation blocks
    let mut prev_permissions = &cert.authority.root_permissions;
    let mut prev_next_key = &cert.authority.next_key;
    let mut prev_hash = cert.authority.block_hash();

    for (i, block) in cert.blocks.iter().enumerate() {
        let block_index = i + 1;

        // 4a. Verify hash chain linkage
        if block.prev_block_hash != prev_hash {
            return Err(CertificateError::BrokenHashChain { block_index });
        }

        // 4b. Verify Ed25519 signature
        let block_payload = block.signing_payload();
        verify_ed25519_strict(prev_next_key, &block_payload, &block.signature)
            .map_err(|_| CertificateError::InvalidSignature { block_index })?;

        // 4c. Verify monotone attenuation
        if !block.effective_permissions.leq(prev_permissions) {
            return Err(CertificateError::MonotoneViolation { block_index });
        }

        // 4c2. Verify sink scope monotonicity (#594)
        let parent_scope = if i == 0 {
            SinkScope::unrestricted()
        } else {
            cert.blocks[i - 1].sink_scope.clone()
        };
        if !parent_scope.contains(&block.sink_scope) {
            return Err(CertificateError::SinkScopeViolation { block_index });
        }

        // 4d. Check expiry
        if now > block.not_after {
            return Err(CertificateError::Expired { block_index });
        }

        // Advance
        prev_permissions = &block.effective_permissions;
        prev_next_key = &block.next_key;
        prev_hash = block.block_hash();
    }

    // 5. Verify proof-of-possession
    let pop_payload = LatticeCertificate::pop_payload_for_block_hash(&prev_hash);
    verify_ed25519_strict(prev_next_key, &pop_payload, &cert.final_signature)
        .map_err(|_| CertificateError::InvalidProofOfPossession)?;

    // 6. Return sealed verified permissions
    let leaf_identity = cert
        .blocks
        .last()
        .map(|b| b.to_identity.clone())
        .unwrap_or_else(|| cert.authority.root_identity.clone());

    let effective_sink_scope = cert
        .blocks
        .last()
        .map(|b| b.sink_scope.clone())
        .unwrap_or_default();

    Ok(VerifiedPermissions::new(
        prev_permissions.clone(),
        cert.blocks.len(),
        cert.authority.root_identity.clone(),
        leaf_identity,
        effective_sink_scope,
    ))
}

// ═══════════════════════════════════════════════════════════════════════════
// INTERNAL HELPERS FOR TESTING
// ═══════════════════════════════════════════════════════════════════════════

/// Expose the raw final_signature for tamper testing.
#[cfg(test)]
impl LatticeCertificate {
    /// Get a mutable reference to the final signature (test-only).
    pub(crate) fn final_signature_mut(&mut self) -> &mut Vec<u8> {
        &mut self.final_signature
    }

    /// Get a mutable reference to the authority block (test-only).
    pub(crate) fn authority_mut(&mut self) -> &mut AuthorityBlock {
        &mut self.authority
    }

    /// Get a mutable reference to the delegation blocks (test-only).
    pub(crate) fn blocks_mut(&mut self) -> &mut Vec<DelegationBlock> {
        &mut self.blocks
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CapabilityLevel;
    use chrono::Duration;

    fn test_rng() -> ring::rand::SystemRandom {
        ring::rand::SystemRandom::new()
    }

    fn generate_key(rng: &dyn SecureRandom) -> Ed25519KeyPair {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(rng).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    #[test]
    fn test_mint_and_verify() {
        let rng = test_rng();
        let root_key = generate_key(&rng);
        let root_pub = root_key.public_key().as_ref().to_vec();
        let not_after = Utc::now() + Duration::hours(8);

        let (cert, _holder_key) = LatticeCertificate::mint(
            PermissionLattice::permissive(),
            "spiffe://test/human/alice".into(),
            not_after,
            &root_key,
            &rng,
        );

        assert_eq!(cert.chain_depth(), 0);
        assert_eq!(cert.root_identity(), "spiffe://test/human/alice");
        assert_eq!(cert.leaf_identity(), "spiffe://test/human/alice");

        let verified = verify_certificate(&cert, &root_pub, Utc::now(), 10).unwrap();
        assert_eq!(verified.chain_depth, 0);
        assert_eq!(verified.root_identity, "spiffe://test/human/alice");
        assert_eq!(verified.leaf_identity, "spiffe://test/human/alice");
    }

    #[test]
    fn test_single_delegation() {
        let rng = test_rng();
        let root_key = generate_key(&rng);
        let root_pub = root_key.public_key().as_ref().to_vec();
        let not_after = Utc::now() + Duration::hours(8);

        let root_perms = PermissionLattice::permissive();
        let (cert, holder_key) = LatticeCertificate::mint(
            root_perms.clone(),
            "spiffe://test/human/alice".into(),
            not_after,
            &root_key,
            &rng,
        );

        let requested = PermissionLattice::restrictive();
        let (cert, _delegatee_key) = cert
            .delegate(
                &requested,
                "spiffe://test/agent/coder-042".into(),
                not_after,
                &holder_key,
                &rng,
            )
            .unwrap();

        assert_eq!(cert.chain_depth(), 1);
        assert_eq!(cert.leaf_identity(), "spiffe://test/agent/coder-042");

        let verified = verify_certificate(&cert, &root_pub, Utc::now(), 10).unwrap();
        assert_eq!(verified.chain_depth, 1);
        assert_eq!(verified.leaf_identity, "spiffe://test/agent/coder-042");

        // Effective permissions should be ≤ root (compare against same root, not fresh one)
        assert!(verified.effective.leq(&root_perms));
    }

    #[test]
    fn test_three_hop_chain() {
        let rng = test_rng();
        let root_key = generate_key(&rng);
        let root_pub = root_key.public_key().as_ref().to_vec();
        let not_after = Utc::now() + Duration::hours(8);

        // Alice → Orchestrator
        let (cert, holder_key) = LatticeCertificate::mint(
            PermissionLattice::permissive(),
            "spiffe://test/human/alice".into(),
            not_after,
            &root_key,
            &rng,
        );

        let mut orch_request = PermissionLattice::permissive();
        orch_request.capabilities.git_push = CapabilityLevel::Never;

        let (cert, orch_key) = cert
            .delegate(
                &orch_request,
                "spiffe://test/agent/orch-001".into(),
                not_after,
                &holder_key,
                &rng,
            )
            .unwrap();

        // Orchestrator → Coder
        let mut coder_request = PermissionLattice::permissive();
        coder_request.capabilities.web_fetch = CapabilityLevel::Never;

        let (cert, coder_key) = cert
            .delegate(
                &coder_request,
                "spiffe://test/agent/coder-042".into(),
                not_after,
                &orch_key,
                &rng,
            )
            .unwrap();

        // Coder → TestRunner
        let (cert, _test_key) = cert
            .delegate(
                &PermissionLattice::read_only(),
                "spiffe://test/agent/test-007".into(),
                not_after,
                &coder_key,
                &rng,
            )
            .unwrap();

        assert_eq!(cert.chain_depth(), 3);

        let verified = verify_certificate(&cert, &root_pub, Utc::now(), 10).unwrap();
        assert_eq!(verified.chain_depth, 3);
        assert_eq!(verified.root_identity, "spiffe://test/human/alice");
        assert_eq!(verified.leaf_identity, "spiffe://test/agent/test-007");

        // TestRunner permissions must be ≤ all ancestors
        let root_perms = &cert.authority.root_permissions;
        assert!(verified.effective.leq(root_perms));
    }

    #[test]
    fn test_wrong_root_key_rejected() {
        let rng = test_rng();
        let root_key = generate_key(&rng);
        let wrong_key = generate_key(&rng);
        let wrong_pub = wrong_key.public_key().as_ref().to_vec();
        let not_after = Utc::now() + Duration::hours(8);

        let (cert, _holder_key) = LatticeCertificate::mint(
            PermissionLattice::permissive(),
            "spiffe://test/human/alice".into(),
            not_after,
            &root_key,
            &rng,
        );

        let result = verify_certificate(&cert, &wrong_pub, Utc::now(), 10);
        assert!(matches!(
            result,
            Err(CertificateError::InvalidSignature { block_index: 0 })
        ));
    }

    #[test]
    fn test_tampered_authority_signature_rejected() {
        let rng = test_rng();
        let root_key = generate_key(&rng);
        let root_pub = root_key.public_key().as_ref().to_vec();
        let not_after = Utc::now() + Duration::hours(8);

        let (mut cert, _holder_key) = LatticeCertificate::mint(
            PermissionLattice::permissive(),
            "spiffe://test/human/alice".into(),
            not_after,
            &root_key,
            &rng,
        );

        // Flip a bit in the authority signature
        cert.authority_mut().signature[0] ^= 0x01;

        let result = verify_certificate(&cert, &root_pub, Utc::now(), 10);
        assert!(matches!(
            result,
            Err(CertificateError::InvalidSignature { block_index: 0 })
        ));
    }

    #[test]
    fn test_tampered_delegation_signature_rejected() {
        let rng = test_rng();
        let root_key = generate_key(&rng);
        let root_pub = root_key.public_key().as_ref().to_vec();
        let not_after = Utc::now() + Duration::hours(8);

        let (cert, holder_key) = LatticeCertificate::mint(
            PermissionLattice::permissive(),
            "spiffe://test/human/alice".into(),
            not_after,
            &root_key,
            &rng,
        );

        let (mut cert, _delegatee_key) = cert
            .delegate(
                &PermissionLattice::restrictive(),
                "spiffe://test/agent/coder".into(),
                not_after,
                &holder_key,
                &rng,
            )
            .unwrap();

        // Flip a bit in the delegation signature
        cert.blocks_mut()[0].signature[0] ^= 0x01;

        let result = verify_certificate(&cert, &root_pub, Utc::now(), 10);
        assert!(matches!(
            result,
            Err(CertificateError::InvalidSignature { block_index: 1 })
        ));
    }

    #[test]
    fn test_expired_authority_rejected() {
        let rng = test_rng();
        let root_key = generate_key(&rng);
        let root_pub = root_key.public_key().as_ref().to_vec();

        // Expired 1 hour ago
        let not_after = Utc::now() - Duration::hours(1);

        let (cert, _holder_key) = LatticeCertificate::mint(
            PermissionLattice::permissive(),
            "spiffe://test/human/alice".into(),
            not_after,
            &root_key,
            &rng,
        );

        let result = verify_certificate(&cert, &root_pub, Utc::now(), 10);
        assert!(matches!(
            result,
            Err(CertificateError::Expired { block_index: 0 })
        ));
    }

    #[test]
    fn test_chain_too_deep_rejected() {
        let rng = test_rng();
        let root_key = generate_key(&rng);
        let root_pub = root_key.public_key().as_ref().to_vec();
        let not_after = Utc::now() + Duration::hours(8);

        let (cert, _holder_key) = LatticeCertificate::mint(
            PermissionLattice::permissive(),
            "spiffe://test/human/alice".into(),
            not_after,
            &root_key,
            &rng,
        );

        // Verify with max_chain_depth = 0 (no delegations allowed)
        let result = verify_certificate(&cert, &root_pub, Utc::now(), 0);
        // Should pass (0 blocks, max 0)
        assert!(result.is_ok());

        // Now delegate once
        let (cert, holder_key) = LatticeCertificate::mint(
            PermissionLattice::permissive(),
            "spiffe://test/human/alice".into(),
            not_after,
            &root_key,
            &rng,
        );

        let (cert, _delegatee_key) = cert
            .delegate(
                &PermissionLattice::restrictive(),
                "spiffe://test/agent/coder".into(),
                not_after,
                &holder_key,
                &rng,
            )
            .unwrap();

        // max_chain_depth = 0 should reject 1 block
        let result = verify_certificate(&cert, &root_pub, Utc::now(), 0);
        assert!(matches!(
            result,
            Err(CertificateError::ChainTooDeep { depth: 1, max: 0 })
        ));
    }

    #[test]
    fn test_expiry_exceeds_parent_rejected() {
        let rng = test_rng();
        let root_key = generate_key(&rng);
        let not_after = Utc::now() + Duration::hours(1);

        let (cert, holder_key) = LatticeCertificate::mint(
            PermissionLattice::permissive(),
            "spiffe://test/human/alice".into(),
            not_after,
            &root_key,
            &rng,
        );

        // Try to delegate with longer expiry
        let result = cert.delegate(
            &PermissionLattice::restrictive(),
            "spiffe://test/agent/coder".into(),
            not_after + Duration::hours(1), // exceeds parent
            &holder_key,
            &rng,
        );

        assert!(matches!(
            result,
            Err(CertificateDelegationError::ExpiryExceedsParent)
        ));
    }

    #[test]
    fn test_key_mismatch_rejected() {
        let rng = test_rng();
        let root_key = generate_key(&rng);
        let wrong_key = generate_key(&rng);
        let not_after = Utc::now() + Duration::hours(8);

        let (cert, _holder_key) = LatticeCertificate::mint(
            PermissionLattice::permissive(),
            "spiffe://test/human/alice".into(),
            not_after,
            &root_key,
            &rng,
        );

        // Try to delegate with the wrong key
        let result = cert.delegate(
            &PermissionLattice::restrictive(),
            "spiffe://test/agent/coder".into(),
            not_after,
            &wrong_key,
            &rng,
        );

        assert!(matches!(
            result,
            Err(CertificateDelegationError::KeyMismatch)
        ));
    }

    #[test]
    fn test_invalid_proof_of_possession() {
        let rng = test_rng();
        let root_key = generate_key(&rng);
        let root_pub = root_key.public_key().as_ref().to_vec();
        let not_after = Utc::now() + Duration::hours(8);

        let (mut cert, _holder_key) = LatticeCertificate::mint(
            PermissionLattice::permissive(),
            "spiffe://test/human/alice".into(),
            not_after,
            &root_key,
            &rng,
        );

        // Tamper with the proof-of-possession
        cert.final_signature_mut()[0] ^= 0x01;

        let result = verify_certificate(&cert, &root_pub, Utc::now(), 10);
        assert!(matches!(
            result,
            Err(CertificateError::InvalidProofOfPossession)
        ));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serde_roundtrip() {
        let rng = test_rng();
        let root_key = generate_key(&rng);
        let root_pub = root_key.public_key().as_ref().to_vec();
        let not_after = Utc::now() + Duration::hours(8);

        let (cert, holder_key) = LatticeCertificate::mint(
            PermissionLattice::permissive(),
            "spiffe://test/human/alice".into(),
            not_after,
            &root_key,
            &rng,
        );

        let (cert, _delegatee_key) = cert
            .delegate(
                &PermissionLattice::restrictive(),
                "spiffe://test/agent/coder".into(),
                not_after,
                &holder_key,
                &rng,
            )
            .unwrap();

        // Serialize → deserialize → verify
        let bytes = cert.to_bytes().unwrap();
        let restored = LatticeCertificate::from_bytes(&bytes).unwrap();
        let verified = verify_certificate(&restored, &root_pub, Utc::now(), 10).unwrap();
        assert_eq!(verified.chain_depth, 1);
    }

    /// #2451 parity: the Aeneas-extracted walk (`portcullis_core::certchain::
    /// chain_attenuates`, proven monotone in `CertChainMonotoneExtracted.lean`)
    /// agrees with `verify_certificate`'s step 4c on REAL, fully signed
    /// certificates — on an honest two-hop chain, and on a chain whose second
    /// hop is validly signed by its parent but WIDENS its permissions (built by
    /// hand: `delegate` refuses to mint one). Everything else in the walk
    /// (signatures, hash linkage, expiry, proof of possession) holds, so the
    /// monotone check is the only thing deciding.
    #[test]
    fn chain_attenuates_agrees_with_verify_certificate() {
        use portcullis_core::certchain::chain_attenuates;

        let rng = test_rng();
        let root_key = generate_key(&rng);
        let root_pub = root_key.public_key().as_ref().to_vec();
        let not_after = Utc::now() + Duration::hours(8);
        let root_perms = PermissionLattice::permissive();

        let (cert, holder) = LatticeCertificate::mint(
            root_perms.clone(),
            "spiffe://test/human/alice".into(),
            not_after,
            &root_key,
            &rng,
        );
        let (cert, child) = cert
            .delegate(
                &PermissionLattice::restrictive(),
                "spiffe://test/agent/a".into(),
                not_after,
                &holder,
                &rng,
            )
            .unwrap();

        // Honest: both accept.
        let effective: Vec<PermissionLattice> = cert
            .blocks
            .iter()
            .map(|b| b.effective_permissions.clone())
            .collect();
        assert!(verify_certificate(&cert, &root_pub, Utc::now(), 10).is_ok());
        assert!(chain_attenuates(&root_perms, &effective));

        // A second hop, correctly signed by the first hop's holder, that
        // claims MORE than its parent: permissive under a restrictive parent.
        let grandchild = generate_key(&rng);
        let parent = cert.blocks.last().unwrap();
        let (_, justification) = meet_with_justification(
            &parent.effective_permissions,
            &PermissionLattice::permissive(),
        );
        let mut widened = DelegationBlock {
            effective_permissions: PermissionLattice::permissive(),
            justification,
            from_identity: parent.to_identity.clone(),
            to_identity: "spiffe://test/agent/b".into(),
            not_after,
            sink_scope: SinkScope::unrestricted(),
            prev_block_hash: parent.block_hash(),
            signature: Vec::new(),
            next_key: grandchild.public_key().as_ref().to_vec(),
        };
        widened.signature = child.sign(&widened.signing_payload()).as_ref().to_vec();
        let pop = LatticeCertificate::pop_payload_for_block_hash(&widened.block_hash());
        let mut blocks = cert.blocks.clone();
        blocks.push(widened);
        let escalated = LatticeCertificate {
            authority: cert.authority.clone(),
            blocks,
            final_signature: grandchild.sign(&pop).as_ref().to_vec(),
        };

        let effective: Vec<PermissionLattice> = escalated
            .blocks
            .iter()
            .map(|b| b.effective_permissions.clone())
            .collect();
        assert!(
            matches!(
                verify_certificate(&escalated, &root_pub, Utc::now(), 10),
                Err(CertificateError::MonotoneViolation { block_index: 2 })
            ),
            "the production walk refuses the widened hop for the monotone reason and no other"
        );
        assert!(
            !chain_attenuates(&root_perms, &effective),
            "the extracted walk refuses the same chain"
        );
    }

    #[test]
    fn test_monotone_attenuation_holds() {
        let rng = test_rng();
        let root_key = generate_key(&rng);
        let not_after = Utc::now() + Duration::hours(8);

        let root_perms = PermissionLattice::permissive();
        let (cert, holder_key) = LatticeCertificate::mint(
            root_perms.clone(),
            "spiffe://test/human/alice".into(),
            not_after,
            &root_key,
            &rng,
        );

        let (cert, _key) = cert
            .delegate(
                &PermissionLattice::restrictive(),
                "spiffe://test/agent/a".into(),
                not_after,
                &holder_key,
                &rng,
            )
            .unwrap();

        // Effective permissions must be ≤ root
        assert!(cert.effective_permissions().leq(&root_perms));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FINGERPRINT TESTS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_fingerprint_deterministic() {
        let rng = test_rng();
        let root_key = generate_key(&rng);
        let not_after = Utc::now() + Duration::hours(8);

        let (cert, _) = LatticeCertificate::mint(
            PermissionLattice::permissive(),
            "spiffe://test/root".into(),
            not_after,
            &root_key,
            &rng,
        );

        let fp1 = cert.fingerprint();
        let fp2 = cert.fingerprint();
        assert_eq!(fp1, fp2, "same certificate must produce same fingerprint");
    }

    #[test]
    fn test_fingerprint_different_for_different_permissions() {
        let rng = test_rng();
        let root_key = generate_key(&rng);
        let not_after = Utc::now() + Duration::hours(8);

        let (cert1, _) = LatticeCertificate::mint(
            PermissionLattice::permissive(),
            "spiffe://test/root".into(),
            not_after,
            &root_key,
            &rng,
        );
        let (cert2, _) = LatticeCertificate::mint(
            PermissionLattice::restrictive(),
            "spiffe://test/root".into(),
            not_after,
            &root_key,
            &rng,
        );

        assert_ne!(
            cert1.fingerprint(),
            cert2.fingerprint(),
            "different permissions must produce different fingerprints"
        );
    }

    #[test]
    fn test_fingerprint_different_for_different_identities() {
        let rng = test_rng();
        let root_key = generate_key(&rng);
        let not_after = Utc::now() + Duration::hours(8);

        let (cert1, _) = LatticeCertificate::mint(
            PermissionLattice::permissive(),
            "spiffe://test/alice".into(),
            not_after,
            &root_key,
            &rng,
        );
        let (cert2, _) = LatticeCertificate::mint(
            PermissionLattice::permissive(),
            "spiffe://test/bob".into(),
            not_after,
            &root_key,
            &rng,
        );

        assert_ne!(
            cert1.fingerprint(),
            cert2.fingerprint(),
            "different identities must produce different fingerprints"
        );
    }

    #[test]
    fn test_fingerprint_changes_with_delegation() {
        let rng = test_rng();
        let root_key = generate_key(&rng);
        let not_after = Utc::now() + Duration::hours(8);

        let (cert, holder_key) = LatticeCertificate::mint(
            PermissionLattice::permissive(),
            "spiffe://test/root".into(),
            not_after,
            &root_key,
            &rng,
        );
        let fp_before = cert.fingerprint();

        let (delegated, _) = cert
            .delegate(
                &PermissionLattice::restrictive(),
                "spiffe://test/agent".into(),
                not_after,
                &holder_key,
                &rng,
            )
            .unwrap();
        let fp_after = delegated.fingerprint();

        assert_ne!(
            fp_before, fp_after,
            "delegation must change the fingerprint"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // Sink scope tests (#594)
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn test_sink_scope_subset_check() {
        let parent = SinkScope {
            allowed_paths: vec!["/workspace/".into(), "/tmp/".into()],
            allowed_hosts: vec!["api.example.com".into()],
            allowed_git_refs: vec![],
        };
        // Child is a subset
        let child = SinkScope {
            allowed_paths: vec!["/workspace/".into()],
            allowed_hosts: vec!["api.example.com".into()],
            allowed_git_refs: vec![],
        };
        assert!(parent.contains(&child));

        // Child tries to widen — NOT a subset
        let wider = SinkScope {
            allowed_paths: vec!["/workspace/".into(), "/etc/".into()],
            allowed_hosts: vec!["api.example.com".into()],
            allowed_git_refs: vec![],
        };
        assert!(!parent.contains(&wider));
    }

    #[test]
    fn test_sink_scope_unrestricted_parent() {
        let unrestricted = SinkScope::unrestricted();
        let restricted = SinkScope {
            allowed_paths: vec!["/workspace/".into()],
            ..Default::default()
        };
        // Unrestricted parent allows any child
        assert!(unrestricted.contains(&restricted));
        assert!(unrestricted.contains(&unrestricted));
    }

    #[test]
    fn test_sink_scope_restricted_parent_rejects_unrestricted_child() {
        let restricted = SinkScope {
            allowed_paths: vec!["/workspace/".into()],
            ..Default::default()
        };
        let unrestricted = SinkScope::unrestricted();
        // Restricted parent REJECTS unrestricted child (widening)
        assert!(!restricted.contains(&unrestricted));
    }

    #[test]
    fn test_delegate_with_sink_scope() {
        let rng = test_rng();
        let root_key = generate_key(&rng);
        let not_after = Utc::now() + Duration::hours(8);

        let (cert, holder_key) = LatticeCertificate::mint(
            PermissionLattice::permissive(),
            "root".into(),
            not_after,
            &root_key,
            &rng,
        );

        // Delegate with path restrictions
        let scope = SinkScope {
            allowed_paths: vec!["/workspace/output/".into()],
            allowed_hosts: vec!["api.example.com".into()],
            ..Default::default()
        };

        let (cert, _delegatee_key) = cert
            .delegate_with_scope(
                &PermissionLattice::restrictive(),
                "agent-1".into(),
                not_after,
                scope.clone(),
                &holder_key,
                &rng,
            )
            .unwrap();

        // Verify — should see the sink scope
        let root_pub = root_key.public_key().as_ref();
        let verified = verify_certificate(&cert, root_pub, Utc::now(), 10).unwrap();
        assert_eq!(verified.sink_scope, scope);
    }

    #[test]
    fn test_delegate_rejects_scope_widening() {
        let rng = test_rng();
        let root_key = generate_key(&rng);
        let not_after = Utc::now() + Duration::hours(8);

        let (cert, holder_key) = LatticeCertificate::mint(
            PermissionLattice::permissive(),
            "root".into(),
            not_after,
            &root_key,
            &rng,
        );

        // First delegation: restrict to /workspace/
        let narrow_scope = SinkScope {
            allowed_paths: vec!["/workspace/".into()],
            ..Default::default()
        };
        let (cert, delegatee_key) = cert
            .delegate_with_scope(
                &PermissionLattice::permissive(),
                "agent-1".into(),
                not_after,
                narrow_scope,
                &holder_key,
                &rng,
            )
            .unwrap();

        // Second delegation: try to WIDEN to /workspace/ + /etc/
        let wider_scope = SinkScope {
            allowed_paths: vec!["/workspace/".into(), "/etc/".into()],
            ..Default::default()
        };
        let result = cert.delegate_with_scope(
            &PermissionLattice::permissive(),
            "agent-2".into(),
            not_after,
            wider_scope,
            &delegatee_key,
            &rng,
        );

        assert!(matches!(
            result,
            Err(CertificateDelegationError::SinkScopeExceedsParent)
        ));
    }

    // ── mint_child (#2432) ───────────────────────────────────────────────

    #[test]
    fn mint_child_succeeds_and_matches_delegate() {
        let rng = test_rng();
        let root_key = generate_key(&rng);
        let not_after = Utc::now() + Duration::hours(8);
        let (cert, holder_key) = LatticeCertificate::mint(
            PermissionLattice::permissive(),
            "spiffe://test/human/alice".into(),
            not_after,
            &root_key,
            &rng,
        );

        let (child, _delegatee_key) = cert
            .mint_child(
                &PermissionLattice::restrictive(),
                "spiffe://test/agent/coder".into(),
                not_after,
                "spawn coder agent",
                &holder_key,
                &rng,
            )
            .expect("a well-formed request within budget/depth must mint");

        assert_eq!(child.chain_depth(), 1);
        assert_eq!(child.leaf_identity(), "spiffe://test/agent/coder");
    }

    /// The load-bearing case: `delegate`/`delegate_with_scope` alone would
    /// silently CLAMP a request for more budget than the parent has
    /// remaining — the plain lattice meet just narrows, it never rejects.
    /// `mint_child` must refuse instead, via `PermissionLattice::delegate_to`.
    #[test]
    fn mint_child_rejects_budget_exceeding_parent() {
        let rng = test_rng();
        let root_key = generate_key(&rng);
        let not_after = Utc::now() + Duration::hours(8);

        let mut parent_perms = PermissionLattice::restrictive();
        parent_perms.budget.max_cost_usd = rust_decimal::Decimal::from(1);
        let (cert, holder_key) = LatticeCertificate::mint(
            parent_perms,
            "spiffe://test/human/alice".into(),
            not_after,
            &root_key,
            &rng,
        );

        let mut over_budget = PermissionLattice::restrictive();
        over_budget.budget.max_cost_usd = rust_decimal::Decimal::from(1_000);

        let result = cert.mint_child(
            &over_budget,
            "spiffe://test/agent/coder".into(),
            not_after,
            "spawn coder agent",
            &holder_key,
            &rng,
        );

        assert!(
            matches!(
                result,
                Err(CertificateMintChildError::Lattice(
                    crate::DelegationError::InsufficientBudget { .. }
                ))
            ),
            "expected InsufficientBudget, got {result:?}"
        );

        // Non-vacuity: `delegate` (the primitive `mint_child` wraps for the
        // chain-level half) does NOT reject this — it silently clamps. If it
        // also rejected, this test wouldn't be distinguishing mint_child's
        // added check from the pre-existing one.
        let plain_delegate_result = cert.delegate(
            &over_budget,
            "spiffe://test/agent/coder".into(),
            not_after,
            &holder_key,
            &rng,
        );
        assert!(
            plain_delegate_result.is_ok(),
            "the pre-existing gap: delegate() must still silently clamp, not reject — \
             otherwise this test no longer demonstrates what mint_child adds"
        );
    }

    /// The other half of the lattice-level check: an already-expired parent
    /// lattice. Distinct from `test_expired_authority_rejected` (which tests
    /// the certificate's own `not_after`, checked at *verification* time) —
    /// this is the lattice's own `TimeLattice`, checked at *mint* time.
    #[test]
    fn mint_child_rejects_expired_parent_lattice() {
        let rng = test_rng();
        let root_key = generate_key(&rng);
        let not_after = Utc::now() + Duration::hours(8);

        let mut parent_perms = PermissionLattice::permissive();
        parent_perms.time = crate::TimeLattice::between(
            Utc::now() - Duration::hours(2),
            Utc::now() - Duration::hours(1),
        );
        let (cert, holder_key) = LatticeCertificate::mint(
            parent_perms,
            "spiffe://test/human/alice".into(),
            not_after,
            &root_key,
            &rng,
        );

        let result = cert.mint_child(
            &PermissionLattice::restrictive(),
            "spiffe://test/agent/coder".into(),
            not_after,
            "spawn coder agent",
            &holder_key,
            &rng,
        );

        assert!(
            matches!(
                result,
                Err(CertificateMintChildError::Lattice(
                    crate::DelegationError::ParentExpired
                ))
            ),
            "expected ParentExpired, got {result:?}"
        );
    }

    /// Depth-exceeded: `mint_child` must surface the SAME `ChainTooDeep`
    /// the chain-level check already gives `delegate`/`delegate_with_scope`
    /// — the lattice-level check ahead of it must not shadow this one.
    #[test]
    fn mint_child_rejects_depth_exceeded() {
        let rng = test_rng();
        let root_key = generate_key(&rng);
        let not_after = Utc::now() + Duration::hours(8);
        let (mut cert, mut holder_key) = LatticeCertificate::mint(
            PermissionLattice::permissive(),
            "spiffe://test/human/alice".into(),
            not_after,
            &root_key,
            &rng,
        );

        // Walk the chain to exactly DEFAULT_MAX_CHAIN_DEPTH.
        for i in 0..DEFAULT_MAX_CHAIN_DEPTH {
            let (next_cert, next_key) = cert
                .mint_child(
                    &PermissionLattice::permissive(),
                    format!("spiffe://test/agent/hop-{i}"),
                    not_after,
                    "hop",
                    &holder_key,
                    &rng,
                )
                .expect("within depth so far");
            cert = next_cert;
            holder_key = next_key;
        }
        assert_eq!(cert.chain_depth(), DEFAULT_MAX_CHAIN_DEPTH);

        // One more must be refused as ChainTooDeep, not silently minted.
        let result = cert.mint_child(
            &PermissionLattice::permissive(),
            "spiffe://test/agent/one-too-many".into(),
            not_after,
            "hop",
            &holder_key,
            &rng,
        );
        assert!(
            matches!(
                result,
                Err(CertificateMintChildError::Chain(
                    CertificateDelegationError::ChainTooDeep { .. }
                ))
            ),
            "expected ChainTooDeep, got {result:?}"
        );
    }

    /// #2474 regression: a validly signed child block whose paths and commands
    /// are UNRESTRICTED (empty allow sets) under a parent restricted to
    /// `src/**` / `cargo test` used to pass the monotone check, because an
    /// empty set is vacuously a subset of anything. `verify_certificate` must
    /// refuse it as `MonotoneViolation`, and an honest narrower child must
    /// still verify.
    #[test]
    fn a_child_claiming_unrestricted_paths_or_commands_is_refused() {
        let rng = test_rng();
        let root_key = generate_key(&rng);
        let root_pub = root_key.public_key().as_ref().to_vec();
        let not_after = Utc::now() + Duration::hours(8);

        let mut root_perms = PermissionLattice::permissive();
        root_perms.paths.allowed = ["src/**".to_string()].into_iter().collect();
        root_perms.commands.allowed = ["cargo test".to_string()].into_iter().collect();
        let (cert, holder) = LatticeCertificate::mint(
            root_perms.clone(),
            "spiffe://test/human/alice".into(),
            not_after,
            &root_key,
            &rng,
        );
        assert!(verify_certificate(&cert, &root_pub, Utc::now(), 10).is_ok());

        // The escalation: unrestricted paths + commands, signed by the holder.
        let mut widened = PermissionLattice::permissive();
        widened.paths.allowed.clear();
        widened.commands.allowed.clear();
        widened.commands.allowed_rules.clear();
        let child_key = generate_key(&rng);
        let (_, justification) = meet_with_justification(&root_perms, &widened);
        let mut block = DelegationBlock {
            effective_permissions: widened,
            justification,
            from_identity: cert.authority.root_identity.clone(),
            to_identity: "spiffe://test/agent/a".into(),
            not_after,
            sink_scope: SinkScope::unrestricted(),
            prev_block_hash: cert.authority.block_hash(),
            signature: Vec::new(),
            next_key: child_key.public_key().as_ref().to_vec(),
        };
        block.signature = holder.sign(&block.signing_payload()).as_ref().to_vec();
        let pop = LatticeCertificate::pop_payload_for_block_hash(&block.block_hash());
        let escalated = LatticeCertificate {
            authority: cert.authority.clone(),
            blocks: vec![block],
            final_signature: child_key.sign(&pop).as_ref().to_vec(),
        };
        assert!(
            matches!(
                verify_certificate(&escalated, &root_pub, Utc::now(), 10),
                Err(CertificateError::MonotoneViolation { block_index: 1 })
            ),
            "an unrestricted child under a restricted parent is a widening"
        );

        // The control: an honest narrower child still verifies.
        let mut narrower = root_perms.clone();
        narrower.paths.allowed = ["src/lib.rs".to_string()].into_iter().collect();
        let (child, _) = cert
            .delegate(
                &narrower,
                "spiffe://test/agent/b".into(),
                not_after,
                &holder,
                &rng,
            )
            .unwrap();
        assert!(verify_certificate(&child, &root_pub, Utc::now(), 10).is_ok());
    }
}
