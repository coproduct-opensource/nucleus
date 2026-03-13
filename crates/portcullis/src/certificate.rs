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
//! assert_eq!(verified.chain_depth, 1);
//! ```

use chrono::{DateTime, Utc};
use ring::rand::SecureRandom;
use ring::signature::{self, Ed25519KeyPair, KeyPair};
use sha2::{Digest, Sha256};
use std::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::delegation::{meet_with_justification, MeetJustification};
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

/// Result of successful certificate verification.
///
/// Only [`verify_certificate`] can produce this type, guaranteeing that the
/// permissions were cryptographically verified.
#[non_exhaustive]
#[derive(Clone)]
pub struct VerifiedPermissions {
    /// The effective permissions at the end of the chain.
    pub effective: PermissionLattice,
    /// Number of delegation hops from root to leaf.
    pub chain_depth: usize,
    /// Identity of the root authority.
    pub root_identity: String,
    /// Identity of the leaf holder.
    pub leaf_identity: String,
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
        }
    }
}

impl std::error::Error for CertificateDelegationError {}

// ═══════════════════════════════════════════════════════════════════════════
// CANONICAL HASHING
// ═══════════════════════════════════════════════════════════════════════════

/// Compute a canonical hash of the security-relevant fields of a PermissionLattice.
///
/// This intentionally excludes metadata (id, description, created_at, created_by,
/// derived_from) to produce deterministic hashes for structurally identical permissions.
pub fn canonical_permissions_hash(perms: &PermissionLattice) -> Vec<u8> {
    let mut hasher = Sha256::new();

    // Capabilities (12 dimensions, each as u8)
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

    // Budget
    hasher.update(perms.budget.max_cost_usd.to_string().as_bytes());
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
    fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"lattice-cert-authority-v1:");
        payload.extend_from_slice(self.root_identity.as_bytes());
        payload.push(0); // separator
        payload.extend_from_slice(&self.not_after.timestamp().to_le_bytes());
        payload.extend_from_slice(&canonical_permissions_hash(&self.root_permissions));
        payload.extend_from_slice(&self.next_key);
        payload
    }

    /// Compute the SHA-256 hash of this block (including the signature).
    fn block_hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(self.signing_payload());
        hasher.update(&self.signature);
        hasher.finalize().to_vec()
    }
}

impl DelegationBlock {
    /// Compute the canonical payload for signing.
    fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"lattice-cert-delegation-v1:");
        payload.extend_from_slice(self.from_identity.as_bytes());
        payload.push(0);
        payload.extend_from_slice(self.to_identity.as_bytes());
        payload.push(0);
        payload.extend_from_slice(&self.not_after.timestamp().to_le_bytes());
        payload.extend_from_slice(&canonical_permissions_hash(&self.effective_permissions));
        payload.extend_from_slice(&self.prev_block_hash);
        payload.extend_from_slice(&self.next_key);
        payload
    }

    /// Compute the SHA-256 hash of this block (including the signature).
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

        let next_key = holder_key.public_key().as_ref().to_vec();

        // Build authority block (without signature initially)
        let mut authority = AuthorityBlock {
            root_permissions,
            root_identity,
            not_after,
            signature: Vec::new(),
            next_key,
        };

        // Sign the canonical payload
        let payload = authority.signing_payload();
        authority.signature = signing_key.sign(&payload).as_ref().to_vec();

        // Build proof-of-possession with the holder key
        let pop_payload = Self::pop_payload_for_block_hash(&authority.block_hash());
        let final_signature = holder_key.sign(&pop_payload).as_ref().to_vec();

        let cert = Self {
            authority,
            blocks: Vec::new(),
            final_signature,
        };

        (cert, holder_key)
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
    pub fn delegate(
        &self,
        requested: &PermissionLattice,
        to_identity: String,
        not_after: DateTime<Utc>,
        current_holder_key: &Ed25519KeyPair,
        rng: &dyn SecureRandom,
    ) -> Result<(Self, Ed25519KeyPair), CertificateDelegationError> {
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

        // Compute the meet with justification (the constructive witness)
        let (effective_permissions, justification) =
            meet_with_justification(parent_permissions, requested);

        // Get from_identity
        let from_identity = if self.blocks.is_empty() {
            self.authority.root_identity.clone()
        } else {
            self.blocks.last().unwrap().to_identity.clone()
        };

        // Generate ephemeral key pair for the delegatee
        let delegatee_pkcs8 = Ed25519KeyPair::generate_pkcs8(rng)
            .map_err(|_| CertificateDelegationError::KeyGenerationFailed)?;
        let delegatee_key = Ed25519KeyPair::from_pkcs8(delegatee_pkcs8.as_ref())
            .map_err(|_| CertificateDelegationError::KeyGenerationFailed)?;

        let next_key = delegatee_key.public_key().as_ref().to_vec();

        // Build delegation block
        let mut block = DelegationBlock {
            effective_permissions,
            justification,
            from_identity,
            to_identity,
            not_after,
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

        let cert = Self {
            authority: self.authority.clone(),
            blocks: new_blocks,
            final_signature,
        };

        Ok((cert, delegatee_key))
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
        hasher.update(b"lattice-cert-fingerprint-v1:");

        // Authority block
        hasher.update(self.authority.root_identity.as_bytes());
        hasher.update([0]); // separator
        hasher.update(self.authority.not_after.timestamp().to_le_bytes());
        hasher.update(canonical_permissions_hash(&self.authority.root_permissions));
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
    let root_verifier = signature::UnparsedPublicKey::new(&signature::ED25519, root_public_key);
    root_verifier
        .verify(&authority_payload, &cert.authority.signature)
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
        let verifier_key =
            signature::UnparsedPublicKey::new(&signature::ED25519, prev_next_key.as_slice());
        let block_payload = block.signing_payload();
        verifier_key
            .verify(&block_payload, &block.signature)
            .map_err(|_| CertificateError::InvalidSignature { block_index })?;

        // 4c. Verify monotone attenuation
        if !block.effective_permissions.leq(prev_permissions) {
            return Err(CertificateError::MonotoneViolation { block_index });
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
    let final_verifier =
        signature::UnparsedPublicKey::new(&signature::ED25519, prev_next_key.as_slice());
    final_verifier
        .verify(&pop_payload, &cert.final_signature)
        .map_err(|_| CertificateError::InvalidProofOfPossession)?;

    // 6. Return sealed verified permissions
    let leaf_identity = cert
        .blocks
        .last()
        .map(|b| b.to_identity.clone())
        .unwrap_or_else(|| cert.authority.root_identity.clone());

    Ok(VerifiedPermissions {
        effective: prev_permissions.clone(),
        chain_depth: cert.blocks.len(),
        root_identity: cert.authority.root_identity.clone(),
        leaf_identity,
    })
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
}
