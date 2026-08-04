//! Signed, attenuation-only capability tokens — `SignedTaskRef`.
//!
//! A [`SignedTaskRef`] is a Biscuit-style capability token: a **chain of
//! signed blocks** where the root block is issued by an authority and every
//! subsequent block is an *attenuation* appended (and signed) by whoever holds
//! the token at that hop. Authority may only **tighten** down the chain — a
//! child block's scope must be a subset of its parent's on every dimension.
//!
//! This mirrors the signing discipline of
//! [`crate::declassify::DeclassifyWitness`]: signatures are dalek Ed25519 over
//! **domain-tagged canonical bytes**, and every re-verification uses
//! [`VerifyingKey::verify_strict`] (never the cofactored `.verify`), so
//! small-order / non-canonical keys and the identity-triple forgery are
//! rejected on the trust path (audit finding M-3, CI
//! `scripts/check-verify-strict.sh`). A **new** domain tag
//! ([`TASKREF_TOKEN_DOMAIN`]), distinct from the witness domain, prevents any
//! cross-protocol signature reuse.
//!
//! ## Chain integrity
//!
//! Each block carries `parent_hash = SHA-256(parent block's signing bytes)`,
//! and each block's signature covers its own `parent_hash`. A block's signing
//! bytes therefore transitively commit to the entire prefix of the chain, so a
//! block cannot be reparented, reordered, or spliced without invalidating a
//! signature.
//!
//! ## Attenuation rule (documented)
//!
//! `child ⊆ parent` holds iff **both**:
//! - **operations**: every operation in the child appears in the parent
//!   (exact set membership — the same discipline as the sink dimension of
//!   [`portcullis_core::delegation::DelegationScope::is_subset_of`]); and
//! - **paths**: the child paths are a subset of the parent paths under
//!   portcullis-core's **audited glob-coverage** matcher (reused verbatim via
//!   [`DelegationScope::is_subset_of`]). A parent pattern covers a child when
//!   it is identical or a `**`-glob that contains it (e.g. parent `"src/**"`
//!   covers child `"src/lib.rs"`; a bare literal `"src"` covers only `"src"`).
//!
//! Chain verification is **check-all-blocks**: *every* adjacent pair must
//! satisfy `child ⊆ parent`. Any widening in any block rejects the whole token.
//!
//! ## Truncation resistance (LOAD-BEARING — read before wiring this in)
//!
//! A token is a `Vec` of blocks; the root block alone is a complete, validly
//! signed token granting the *full, un-attenuated* root scope. A holder of an
//! attenuated token (root → child) can therefore **drop its own child block**
//! and present just the root — recovering the parent's wider authority. That is
//! privilege escalation by truncation.
//!
//! The sole defense is [`verify`](SignedTaskRef::verify)'s `expected_nonce`,
//! which is checked against the **effective (last) block** and supplied
//! **out-of-band** (never read from the token). A truncated token ends on a
//! block whose nonce differs from the one the authority assigned to *this*
//! holder's tail, so it fails [`TokenError::NonceMismatch`]. This holds **only
//! if** the verifier obtains `expected_nonce` from a host/kernel-pinned channel
//! that the holding agent cannot read or influence. Any wiring that lets the
//! agent supply, observe-then-echo, or mutate `expected_nonce` — or that derives
//! it from the presented token — reopens the truncation escalation. This is a
//! runtime-threading (PR2) obligation, flagged here so it cannot be lost.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use portcullis_core::delegation::DelegationScope;
use portcullis_core::Operation;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain tag for TaskRef capability-token block signatures. Distinct from
/// `declassify::WITNESS_DOMAIN` so a signature minted for one protocol can
/// never be replayed as the other.
const TASKREF_TOKEN_DOMAIN: &[u8] = b"nucleus-provenance-memory/taskref-token/v1\0";

/// The scope a token block grants: a set of operations and a set of paths.
/// Empty lists mean "nothing in that dimension" (allowlist semantics, matching
/// [`DelegationScope`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenScope {
    /// Operations considered in-scope.
    pub allowed_operations: Vec<Operation>,
    /// Path patterns considered in-scope (glob-coverage semantics on verify).
    pub allowed_paths: Vec<String>,
}

impl TokenScope {
    /// Build a scope from operations and paths.
    pub fn new(allowed_operations: Vec<Operation>, allowed_paths: Vec<String>) -> Self {
        Self {
            allowed_operations,
            allowed_paths,
        }
    }

    /// Is `self` a subset of `parent` on **every** dimension?
    ///
    /// Operations use exact set membership; paths reuse the audited
    /// glob-coverage subset check from [`DelegationScope::is_subset_of`]. See
    /// the module docs for the exact rule.
    pub fn is_subset_of(&self, parent: &TokenScope) -> bool {
        let ops_ok = self
            .allowed_operations
            .iter()
            .all(|op| parent.allowed_operations.contains(op));

        // Reuse portcullis-core's audited path-coverage matcher by lifting the
        // path dimension into a DelegationScope (other dimensions left empty,
        // so they never affect the verdict).
        let child = DelegationScope {
            allowed_paths: self.allowed_paths.clone(),
            allowed_sinks: Vec::new(),
            allowed_repos: Vec::new(),
        };
        let parent = DelegationScope {
            allowed_paths: parent.allowed_paths.clone(),
            allowed_sinks: Vec::new(),
            allowed_repos: Vec::new(),
        };
        ops_ok && child.is_subset_of(&parent)
    }
}

/// The signable content of one chain block: scope + lineage + freshness +
/// issuer identity. Everything here is covered by the block's signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockClaim {
    /// The authority this block grants (attenuated from its parent).
    pub scope: TokenScope,
    /// SHA-256 of the parent block's signing bytes; `None` for the root block.
    pub parent_hash: Option<[u8; 32]>,
    /// Per-block anti-replay nonce.
    pub nonce: [u8; 16],
    /// Issue time (caller-supplied clock; opaque units, compared against
    /// `now` at verify).
    pub issued_at: u64,
    /// Time-to-live; the block is expired once `issued_at + ttl < now`.
    pub ttl: u64,
    /// Ed25519 verifying-key bytes of the block's issuer/attenuator.
    pub issuer_vk: [u8; 32],
}

/// A [`BlockClaim`] plus the issuer's Ed25519 signature over its
/// domain-tagged canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBlock {
    /// The signed content.
    pub claim: BlockClaim,
    /// Ed25519 signature (64 bytes) over `signing_bytes(task_id, &claim)`.
    pub sig: Vec<u8>,
}

/// A signed, attenuation-only capability token: a `task_id` plus a non-empty
/// chain of [`SignedBlock`]s (root first, most-attenuated last).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTaskRef {
    /// Stable task identifier, bound into every block's signature.
    pub task_id: String,
    /// The attenuation chain: `blocks[0]` is the root, each later block a
    /// tightening appended by its holder.
    pub blocks: Vec<SignedBlock>,
}

/// Why a token failed verification. Every variant is fail-closed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    /// The token carries no blocks (unsigned / empty).
    #[error("token has no signature blocks (unsigned)")]
    Empty,
    /// The root block's issuer is not the trusted root key.
    #[error("root issuer does not match the trusted root key")]
    RootIssuerMismatch,
    /// A non-root block declared no `parent_hash`, or a root block declared one.
    #[error("block {block} has malformed lineage (parent_hash placement)")]
    MalformedLineage {
        /// Index of the offending block.
        block: usize,
    },
    /// A block's `parent_hash` does not match the actual parent's hash — the
    /// chain was spliced or reordered.
    #[error("block {block} parent_hash does not match its parent")]
    BrokenLineage {
        /// Index of the offending block.
        block: usize,
    },
    /// A block's signature did not verify under `verify_strict` (tampered
    /// scope, wrong key, malformed/forged, or small-order issuer key).
    #[error("block {block} signature failed strict verification")]
    BadSignature {
        /// Index of the offending block.
        block: usize,
    },
    /// A block widened authority relative to its parent (attenuation-only
    /// violation).
    #[error("block {block} widens authority beyond its parent")]
    ScopeWidened {
        /// Index of the offending block.
        block: usize,
    },
    /// A block is expired (`issued_at + ttl < now`).
    #[error("block {block} is expired")]
    Expired {
        /// Index of the offending block.
        block: usize,
    },
    /// The effective (last) block's nonce does not match the expected nonce
    /// (replay / stale token).
    #[error("effective nonce mismatch (replay)")]
    NonceMismatch,
}

/// Domain-tagged canonical bytes a block's issuer signs over. Binds the
/// token's `task_id` and the full [`BlockClaim`] (including `parent_hash`,
/// which transitively commits to the whole chain prefix).
fn signing_bytes(task_id: &str, claim: &BlockClaim) -> Vec<u8> {
    let mut out = Vec::with_capacity(TASKREF_TOKEN_DOMAIN.len() + 160);
    out.extend_from_slice(TASKREF_TOKEN_DOMAIN);
    serde_json::to_writer(&mut out, &(task_id, claim))
        .expect("taskref-token claim serialization is infallible");
    out
}

/// SHA-256 of a block's signing bytes — the value a child block records as its
/// `parent_hash`.
fn block_hash(task_id: &str, claim: &BlockClaim) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(signing_bytes(task_id, claim));
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

impl SignedTaskRef {
    /// Issue a fresh root token: a single block granting `scope`, signed by
    /// `issuer`. (The `SigningKey` is supplied by the caller — e.g. a
    /// SPIRE-issued key — never generated here.)
    pub fn issue(
        task_id: impl Into<String>,
        scope: TokenScope,
        nonce: [u8; 16],
        issued_at: u64,
        ttl: u64,
        issuer: &SigningKey,
    ) -> Self {
        let task_id = task_id.into();
        let claim = BlockClaim {
            scope,
            parent_hash: None,
            nonce,
            issued_at,
            ttl,
            issuer_vk: issuer.verifying_key().to_bytes(),
        };
        let sig = issuer
            .sign(&signing_bytes(&task_id, &claim))
            .to_bytes()
            .to_vec();
        Self {
            task_id,
            blocks: vec![SignedBlock { claim, sig }],
        }
    }

    /// Append an attenuation block signed by `attenuator`, granting
    /// `child_scope`. This is **purely mechanical**: it does not itself
    /// enforce `child ⊆ parent` — that is the verifier's job (check-all-blocks
    /// in [`verify`](Self::verify)), so an adversarial widening token can be
    /// constructed and must still be rejected at verification.
    ///
    /// The new block's `parent_hash` is bound to the current tail block, so
    /// the chain cannot be reordered or spliced.
    pub fn attenuate(
        &self,
        child_scope: TokenScope,
        nonce: [u8; 16],
        issued_at: u64,
        ttl: u64,
        attenuator: &SigningKey,
    ) -> Self {
        let mut next = self.clone();
        let parent = next
            .blocks
            .last()
            .expect("a SignedTaskRef always has at least the root block");
        let parent_hash = block_hash(&next.task_id, &parent.claim);
        let claim = BlockClaim {
            scope: child_scope,
            parent_hash: Some(parent_hash),
            nonce,
            issued_at,
            ttl,
            issuer_vk: attenuator.verifying_key().to_bytes(),
        };
        let sig = attenuator
            .sign(&signing_bytes(&next.task_id, &claim))
            .to_bytes()
            .to_vec();
        next.blocks.push(SignedBlock { claim, sig });
        next
    }

    /// The effective (most-attenuated) scope — the last block's scope. `None`
    /// only for an empty (invalid) token.
    pub fn effective_scope(&self) -> Option<&TokenScope> {
        self.blocks.last().map(|b| &b.claim.scope)
    }

    /// **The verification gate.** Returns the effective granted scope, or a
    /// [`TokenError`]. Fail-closed on every check. `now` is caller-supplied
    /// (verify never reads the system clock — keeps callers deterministic).
    ///
    /// Checks, in order, for the whole chain:
    /// 1. non-empty;
    /// 2. root block's `issuer_vk == root_issuer` (pin the trust anchor);
    /// 3. each block's signature verifies under `verify_strict` (rejects
    ///    tamper, wrong-key, and small-order / non-canonical issuer keys);
    /// 4. lineage: root has no `parent_hash`; every child's `parent_hash`
    ///    equals its parent's actual hash;
    /// 5. attenuation: every child's scope ⊆ its parent's scope
    ///    (check-all-blocks — any widening anywhere rejects);
    /// 6. freshness: no block is expired (`issued_at + ttl < now`);
    /// 7. the effective (last) block's nonce equals `expected_nonce`.
    pub fn verify(
        &self,
        root_issuer: &[u8; 32],
        now: u64,
        expected_nonce: &[u8; 16],
    ) -> Result<&TokenScope, TokenError> {
        // 1. Non-empty.
        if self.blocks.is_empty() {
            return Err(TokenError::Empty);
        }

        // 2. Pin the trust anchor: the root must be the expected issuer.
        if &self.blocks[0].claim.issuer_vk != root_issuer {
            return Err(TokenError::RootIssuerMismatch);
        }

        for (i, block) in self.blocks.iter().enumerate() {
            // 4a. Lineage placement: root has no parent, children must have one.
            if i == 0 {
                if block.claim.parent_hash.is_some() {
                    return Err(TokenError::MalformedLineage { block: i });
                }
            } else if block.claim.parent_hash.is_none() {
                return Err(TokenError::MalformedLineage { block: i });
            }

            // 3. Strict signature verification over the domain-tagged bytes.
            let vk = VerifyingKey::from_bytes(&block.claim.issuer_vk)
                .map_err(|_| TokenError::BadSignature { block: i })?;
            let sig = Signature::from_slice(&block.sig)
                .map_err(|_| TokenError::BadSignature { block: i })?;
            let msg = signing_bytes(&self.task_id, &block.claim);
            // verify_strict (NOT .verify): rejects small-order / non-canonical
            // keys and the identity-triple forgery (audit M-3).
            vk.verify_strict(&msg, &sig)
                .map_err(|_| TokenError::BadSignature { block: i })?;

            // 6. Freshness: reject expired blocks. Saturating add so a crafted
            // overflow can never wrap the deadline earlier than `issued_at`.
            let deadline = block.claim.issued_at.saturating_add(block.claim.ttl);
            if deadline < now {
                return Err(TokenError::Expired { block: i });
            }

            // 4b + 5. Lineage hash + attenuation, against the parent.
            if i > 0 {
                let parent = &self.blocks[i - 1];
                let expected_parent_hash = block_hash(&self.task_id, &parent.claim);
                if block.claim.parent_hash != Some(expected_parent_hash) {
                    return Err(TokenError::BrokenLineage { block: i });
                }
                if !block.claim.scope.is_subset_of(&parent.claim.scope) {
                    return Err(TokenError::ScopeWidened { block: i });
                }
            }
        }

        // 7. Effective-nonce freshness (anti-replay).
        let effective = self.blocks.last().expect("non-empty checked above");
        if &effective.claim.nonce != expected_nonce {
            return Err(TokenError::NonceMismatch);
        }

        Ok(&effective.claim.scope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        // from_bytes is decode-only — no CSPRNG (production keys come from SPIRE).
        SigningKey::from_bytes(&[seed; 32])
    }

    const N0: [u8; 16] = [0u8; 16];
    const N1: [u8; 16] = [1u8; 16];
    const N2: [u8; 16] = [2u8; 16];

    fn root_scope() -> TokenScope {
        TokenScope::new(
            vec![Operation::ReadFiles, Operation::EditFiles],
            vec!["src/**".to_string()],
        )
    }

    fn root_token(issuer: &SigningKey) -> SignedTaskRef {
        SignedTaskRef::issue("task-1", root_scope(), N0, 1_000, 500, issuer)
    }

    // 1. A valid, honestly-signed token verifies under the issuer key.
    #[test]
    fn valid_token_verifies() {
        let issuer = key(1);
        let vk = issuer.verifying_key().to_bytes();
        let token = root_token(&issuer);
        let scope = token
            .verify(&vk, 1_200, &N0)
            .expect("honest token must verify");
        assert_eq!(scope, &root_scope());
    }

    // 2a. A tampered scope byte (mutated after signing) is rejected.
    #[test]
    fn tampered_scope_is_rejected() {
        let issuer = key(1);
        let vk = issuer.verifying_key().to_bytes();
        let mut token = root_token(&issuer);
        // Widen the signed scope after the fact — signature no longer matches.
        token.blocks[0]
            .claim
            .scope
            .allowed_operations
            .push(Operation::RunBash);
        assert_eq!(
            token.verify(&vk, 1_200, &N0),
            Err(TokenError::BadSignature { block: 0 })
        );
    }

    // 2b. A signature made by the wrong key is rejected (root issuer pinned).
    #[test]
    fn wrong_key_signature_is_rejected() {
        let issuer = key(1);
        let attacker = key(9);
        // Token signed by the attacker, but verified against the honest root.
        let token = root_token(&attacker);
        let honest_vk = issuer.verifying_key().to_bytes();
        assert_eq!(
            token.verify(&honest_vk, 1_200, &N0),
            Err(TokenError::RootIssuerMismatch)
        );
    }

    // 3. An unsigned / empty-block token is rejected.
    #[test]
    fn empty_token_is_rejected() {
        let issuer = key(1);
        let vk = issuer.verifying_key().to_bytes();
        let token = SignedTaskRef {
            task_id: "task-1".to_string(),
            blocks: Vec::new(),
        };
        assert_eq!(token.verify(&vk, 1_200, &N0), Err(TokenError::Empty));
    }

    // 3b. A block with an empty signature is rejected (malformed → BadSignature).
    #[test]
    fn empty_signature_block_is_rejected() {
        let issuer = key(1);
        let vk = issuer.verifying_key().to_bytes();
        let mut token = root_token(&issuer);
        token.blocks[0].sig = Vec::new();
        assert_eq!(
            token.verify(&vk, 1_200, &N0),
            Err(TokenError::BadSignature { block: 0 })
        );
    }

    // 4. child ⊆ parent attenuation is accepted (check-all-blocks passes).
    #[test]
    fn child_subset_attenuation_accepted() {
        let root = key(1);
        let child = key(2);
        let root_vk = root.verifying_key().to_bytes();
        let token = root_token(&root).attenuate(
            // Tighten: drop EditFiles, narrow paths under src/**.
            TokenScope::new(vec![Operation::ReadFiles], vec!["src/lib.rs".to_string()]),
            N1,
            1_000,
            500,
            &child,
        );
        let scope = token
            .verify(&root_vk, 1_200, &N1)
            .expect("subset attenuation must verify");
        assert_eq!(
            scope,
            &TokenScope::new(vec![Operation::ReadFiles], vec!["src/lib.rs".to_string()])
        );
    }

    // 5a. A child that adds an operation not held by the parent is rejected.
    #[test]
    fn widening_operation_is_rejected() {
        let root = key(1);
        let child = key(2);
        let root_vk = root.verifying_key().to_bytes();
        let token = root_token(&root).attenuate(
            // RunBash is NOT in the parent scope → widening.
            TokenScope::new(
                vec![Operation::ReadFiles, Operation::RunBash],
                vec!["src/lib.rs".to_string()],
            ),
            N1,
            1_000,
            500,
            &child,
        );
        assert_eq!(
            token.verify(&root_vk, 1_200, &N1),
            Err(TokenError::ScopeWidened { block: 1 })
        );
    }

    // 5b. A child that adds a path not covered by the parent is rejected — and
    // it is caught even when it is a *deep* block (check-ALL-blocks).
    #[test]
    fn widening_path_in_deep_block_is_rejected() {
        let root = key(1);
        let child = key(2);
        let grandchild = key(3);
        let root_vk = root.verifying_key().to_bytes();
        let token = root_token(&root)
            .attenuate(
                TokenScope::new(vec![Operation::ReadFiles], vec!["src/**".to_string()]),
                N1,
                1_000,
                500,
                &child,
            )
            .attenuate(
                // "etc/**" is outside the parent's "src/**" → widening at block 2.
                TokenScope::new(vec![Operation::ReadFiles], vec!["etc/**".to_string()]),
                N2,
                1_000,
                500,
                &grandchild,
            );
        assert_eq!(
            token.verify(&root_vk, 1_200, &N2),
            Err(TokenError::ScopeWidened { block: 2 })
        );
    }

    // 6a. An expired token (issued_at + ttl < now) is rejected.
    #[test]
    fn expired_token_is_rejected() {
        let issuer = key(1);
        let vk = issuer.verifying_key().to_bytes();
        let token = root_token(&issuer); // issued_at=1000, ttl=500 → deadline 1500
        assert_eq!(
            token.verify(&vk, 1_501, &N0),
            Err(TokenError::Expired { block: 0 })
        );
        // Exactly at the deadline is still valid (deadline < now is the reject).
        assert!(token.verify(&vk, 1_500, &N0).is_ok());
    }

    // 6b. A replay with the wrong (stale) nonce is rejected.
    #[test]
    fn nonce_mismatch_is_rejected() {
        let issuer = key(1);
        let vk = issuer.verifying_key().to_bytes();
        let token = root_token(&issuer);
        // Correct signature, in-date, but the presenter's nonce is stale.
        assert_eq!(
            token.verify(&vk, 1_200, &N1),
            Err(TokenError::NonceMismatch)
        );
    }

    // 6c. A spliced/reordered chain (bad parent_hash) is rejected.
    #[test]
    fn broken_lineage_is_rejected() {
        let root = key(1);
        let child = key(2);
        let root_vk = root.verifying_key().to_bytes();
        let mut token = root_token(&root).attenuate(
            TokenScope::new(vec![Operation::ReadFiles], vec!["src/lib.rs".to_string()]),
            N1,
            1_000,
            500,
            &child,
        );
        // Corrupt the child's parent_hash → lineage no longer chains.
        token.blocks[1].claim.parent_hash = Some([0xAB; 32]);
        // Re-sign so the signature itself is valid; only the hash is wrong.
        token.blocks[1].sig = child
            .sign(&signing_bytes(&token.task_id, &token.blocks[1].claim))
            .to_bytes()
            .to_vec();
        assert_eq!(
            token.verify(&root_vk, 1_200, &N1),
            Err(TokenError::BrokenLineage { block: 1 })
        );
    }

    // 7. M-3 strong-binding regression: a small-order / non-canonical issuer
    //    key with the identity-triple signature must be REJECTED by
    //    verify_strict. The Ed25519 identity/neutral key (`[1, 0, …, 0]`) with
    //    signature `R = identity, s = 0` satisfies the *cofactored* equation for
    //    every message, so non-strict `.verify()` ACCEPTS it — a forged root.
    //    `verify_strict()` rejects the small-order point. If the verify site is
    //    reverted to non-strict `.verify()`, this token would (wrongly) pass.
    #[test]
    fn small_order_issuer_key_is_rejected_by_verify_strict() {
        // Identity/neutral point encoding — a small-order public key.
        let mut id = [0u8; 32];
        id[0] = 1;
        // Identity-triple signature: R = identity encoding, s = 0.
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&id);

        let claim = BlockClaim {
            scope: root_scope(),
            parent_hash: None,
            nonce: N0,
            issued_at: 1_000,
            ttl: 500,
            issuer_vk: id,
        };
        let token = SignedTaskRef {
            task_id: "task-1".to_string(),
            blocks: vec![SignedBlock {
                claim,
                sig: sig_bytes.to_vec(),
            }],
        };
        // Pin the trust anchor to the small-order key itself, so the ONLY thing
        // standing between the forgery and acceptance is verify_strict.
        assert_eq!(
            token.verify(&id, 1_200, &N0),
            Err(TokenError::BadSignature { block: 0 }),
            "small-order identity key must be REJECTED by verify_strict; a revert \
             to non-strict verify() would ACCEPT this forged root token"
        );
    }

    // Extra: an all-zeros issuer key (non-canonical / not a valid point) is
    // rejected too — from_bytes/verify_strict refuse it.
    #[test]
    fn all_zeros_issuer_key_is_rejected() {
        let claim = BlockClaim {
            scope: root_scope(),
            parent_hash: None,
            nonce: N0,
            issued_at: 1_000,
            ttl: 500,
            issuer_vk: [0u8; 32],
        };
        let token = SignedTaskRef {
            task_id: "task-1".to_string(),
            blocks: vec![SignedBlock {
                claim,
                sig: vec![0u8; 64],
            }],
        };
        assert_eq!(
            token.verify(&[0u8; 32], 1_200, &N0),
            Err(TokenError::BadSignature { block: 0 })
        );
    }
}
