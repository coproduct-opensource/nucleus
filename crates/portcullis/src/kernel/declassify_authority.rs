//! The kernel's declassification authority surface: trusted-key configuration
//! and one-shot token application. Extracted from `kernel.rs` (line ratchet);
//! a CHILD module of `kernel`, so the impl reaches the kernel's private fields
//! (`trusted_public_keys`, `flow_graph` — incl. its shared release ledger) without
//! widening their visibility.

use super::{DenyReason, Kernel};
use portcullis_core::declassify::{DeclassificationToken, TokenApplyResult};

/// The 32-byte one-shot authorization id for an Ed25519 declassification token:
/// SHA-256 of its deterministic signature. Sharing a fixed-width id with the
/// k-of-n path lets both mint policies burn against the one
/// [`FlowGraph::release_burn_ledger`](crate::flow_graph::FlowGraph).
fn release_burn_id(signature: &[u8; 64]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"nucleus.declassify.token.v1");
    h.update(signature);
    h.finalize().into()
}

/// A declassification token whose Ed25519 signature the kernel has checked
/// against its trusted governor keys — the ONLY thing
/// [`FlowGraph::apply_verified`](crate::flow_graph::FlowGraph::apply_verified)
/// accepts.
///
/// # The defect this closes (2026-09-27)
///
/// Until this type existed, the signature check lived INSIDE the kernel's apply
/// path, and the graph mutator it guarded sat beside it with the same
/// visibility: `FlowGraph::apply_token` was `pub` and verified nothing, and
/// `DeclassScope` had `pub` fields, so any caller holding a `&mut FlowGraph`
/// could record a release for any node and any sink — by calling the unsigned
/// primitive, or by writing the scope as a struct literal and handing it to
/// `record_release_scope`. The live endpoint happened to go through the checked
/// path. Nothing made it.
///
/// Now the check and the effect are two calls joined by this value (ADR 0007
/// C-1, C-4): [`Kernel::verify_declassification`] is its only constructor (the
/// fields are private to this module), and `apply_verified` takes it BY VALUE,
/// so one verification pays for exactly one application. It is `!Clone` and
/// `!Copy` for the same reason; `DeclassificationToken` itself stays plain,
/// cloneable request data — it is the claim, this is the evidence.
///
/// A verification spent twice does not compile — the second call is the only
/// line that can fail, and it fails because `v` was moved:
///
/// ```compile_fail
/// use portcullis::flow_graph::FlowGraph;
/// use portcullis::kernel::Kernel;
/// use portcullis::PermissionLattice;
/// use portcullis_core::declassify::DeclassificationToken;
///
/// fn spend(kernel: &Kernel, g: &mut FlowGraph, token: &DeclassificationToken) {
///     let Ok(v) = kernel.verify_declassification(token) else { return };
///     let _ = g.apply_verified(v, 0);
///
///     // Everything above this line is proven to compile by the block below.
///     let _ = g.apply_verified(v, 0);
/// }
/// # let _ = PermissionLattice::default();
/// ```
///
/// The block below is that one character-for-character, minus the last
/// statement, and it must pass (the pairing is what makes the first block
/// mean something — see `FlowGraph::reset_session_ceiling`):
///
/// ```
/// use portcullis::flow_graph::FlowGraph;
/// use portcullis::kernel::Kernel;
/// use portcullis::PermissionLattice;
/// use portcullis_core::declassify::DeclassificationToken;
///
/// fn spend(kernel: &Kernel, g: &mut FlowGraph, token: &DeclassificationToken) {
///     let Ok(v) = kernel.verify_declassification(token) else { return };
///     let _ = g.apply_verified(v, 0);
/// }
/// # let _ = PermissionLattice::default();
/// ```
#[must_use = "a verified declassification does nothing until it is spent by FlowGraph::apply_verified"]
#[derive(Debug)]
pub struct VerifiedDeclassification {
    token: DeclassificationToken,
    burn_id: [u8; 32],
    /// The deadline this evidence stops being spendable at — the signed
    /// token's `valid_until`, fixed at mint. `apply_verified` decides expiry
    /// from THIS field and reads no other deadline, so the witness is a right
    /// with a validity interval rather than one that authorises at t=∞.
    valid_until: u64,
}

impl VerifiedDeclassification {
    /// The verified token (read-only — the witness is spent whole, never
    /// re-assembled from parts).
    pub fn token(&self) -> &DeclassificationToken {
        &self.token
    }

    /// The node the verified token releases.
    pub fn target_node_id(&self) -> u64 {
        self.token.target_node_id
    }

    /// The deadline after which `apply_verified` refuses this witness `Expired`.
    pub fn valid_until(&self) -> u64 {
        self.valid_until
    }

    /// Consume the witness into what the graph needs to spend it: the token,
    /// its one-shot burn id, and its deadline. `pub(crate)` and by value — the
    /// one caller is `FlowGraph::apply_verified`; nothing outside the crate can
    /// open it, and nothing inside can put it back together.
    pub(crate) fn into_parts(self) -> (DeclassificationToken, [u8; 32], u64) {
        (self.token, self.burn_id, self.valid_until)
    }
}

impl Kernel {
    /// Set trusted Ed25519 public keys for declassification token verification.
    ///
    /// When set, [`verify_declassification`](Self::verify_declassification)
    /// verifies token signatures against these keys. Supports key rotation by
    /// accepting multiple keys.
    ///
    /// When no trusted keys are set (the default), verification is REFUSED
    /// outright — fail-closed; see the body of `verify_declassification`.
    ///
    /// This key set is what the North Star means by "a governor": a
    /// principal holding a key configured here. It is configuration, not
    /// something any agent-reachable path may write.
    pub fn set_trusted_keys(&mut self, keys: Vec<[u8; 32]>) {
        self.trusted_public_keys = keys;
    }

    /// **The only mint of [`VerifiedDeclassification`].** Checks that `token`
    /// carries a valid Ed25519 signature from one of the kernel's trusted
    /// governor keys and returns the witness that
    /// [`FlowGraph::apply_verified`](crate::flow_graph::FlowGraph::apply_verified)
    /// spends.
    ///
    /// Refuses (`InvalidDeclassification`) when no trusted keys are configured —
    /// fail-closed, there is no unsigned fallback — and when the signature does
    /// not verify under any of them.
    ///
    /// The one-shot check is NOT here: the burn ledger lives on the graph the
    /// release is recorded on (so the k-of-n memory path shares it), and the
    /// kernel does not hold that graph. `apply_verified` decides replay, once,
    /// against the ledger it is about to write. The id it checks is computed
    /// here, from the signature just verified, so it cannot be chosen by the
    /// caller.
    pub fn verify_declassification(
        &self,
        token: &DeclassificationToken,
    ) -> Result<VerifiedDeclassification, DenyReason> {
        // Fail-closed (most-paranoid #3): declassification weakens information-flow
        // labels, so it MUST be cryptographically authorized. With no trusted keys
        // configured there is no authority to verify against, so refuse outright.
        if self.trusted_public_keys.is_empty() {
            tracing::warn!(
                target_node = token.target_node_id,
                "declassification refused: no trusted public keys configured (fail-closed)"
            );
            return Err(DenyReason::InvalidDeclassification {
                detail: "no trusted public keys configured — declassification refused \
                         (fail-closed); configure trusted keys and sign the token"
                    .to_string(),
            });
        }
        let key_refs: Vec<&[u8]> = self
            .trusted_public_keys
            .iter()
            .map(|k| k.as_slice())
            .collect();
        if crate::token_sign::verify_token_any_key(token, &key_refs).is_err() {
            return Err(DenyReason::InvalidDeclassification {
                detail: "token signature verification failed — not signed by any trusted key"
                    .to_string(),
            });
        }
        // One-shot (HC-6): the deterministic Ed25519 signature identifies exactly
        // one authorization. Its burn id is a 32-byte SHA-256 over the signature —
        // the width the SHARED `FlowGraph::release_burn_ledger` uses so the keyless
        // k-of-n memory path burns against the same ledger (Phase 4).
        Ok(VerifiedDeclassification {
            burn_id: release_burn_id(&token.signature),
            valid_until: token.valid_until,
            token: token.clone(),
        })
    }

    /// Verify `token` and apply it to the kernel's OWN flow graph: exactly
    /// [`verify_declassification`](Self::verify_declassification) followed by
    /// [`FlowGraph::apply_verified`](crate::flow_graph::FlowGraph::apply_verified).
    /// A composition, not a second decider — every refusal comes from one of
    /// those two.
    ///
    /// Returns `Err(DenyReason::InvalidDeclassification)` for a missing trust
    /// root or bad signature, `Err(DenyReason::DeclassificationReplayed)` for a
    /// spent token, and `Ok(TokenApplyResult)` otherwise (expired /
    /// precondition-unmet / content-mismatch are non-error, non-burning
    /// rejections).
    pub fn apply_declassification_token(
        &mut self,
        token: &DeclassificationToken,
    ) -> Result<TokenApplyResult, DenyReason> {
        let v = self.verify_declassification(token)?;
        self.flow_graph.apply_verified(v, now())
    }

    /// Verify `token` and apply it to an EXTERNALLY-SUPPLIED flow graph (Phase
    /// 4.5 re-home). Same composition as
    /// [`apply_declassification_token`](Self::apply_declassification_token), but
    /// the scope is recorded on — and the one-shot burn is spent against — the
    /// `graph` the caller passes, not the kernel's own `flow_graph`.
    ///
    /// The live endpoint (`POST /v1/declassify`) spells the two calls out
    /// itself; this remains for callers that want them fused.
    pub fn apply_declassification_token_on(
        &self,
        graph: &mut crate::flow_graph::FlowGraph,
        token: &DeclassificationToken,
    ) -> Result<TokenApplyResult, DenyReason> {
        let v = self.verify_declassification(token)?;
        graph.apply_verified(v, now())
    }
}

fn now() -> u64 {
    chrono::Utc::now().timestamp() as u64
}
