//! The kernel's declassification authority surface: trusted-key configuration
//! and one-shot token application. Extracted from `kernel.rs` (line ratchet);
//! a CHILD module of `kernel`, so the impl reaches the kernel's private fields
//! (`trusted_public_keys`, `flow_graph` — incl. its shared release ledger) without
//! widening their visibility.

use super::{DenyReason, Kernel};

/// The 32-byte one-shot authorization id for an Ed25519 declassification token:
/// SHA-256 of its deterministic signature. Sharing a fixed-width id with the
/// k-of-n path lets both mint policies burn against the one
/// [`FlowGraph::release_burn_ledger`](crate::flow_graph::FlowGraph).
#[cfg(feature = "crypto")]
fn release_burn_id(signature: &[u8; 64]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"nucleus.declassify.token.v1");
    h.update(signature);
    h.finalize().into()
}

#[cfg(feature = "crypto")]
impl Kernel {
    /// Set trusted Ed25519 public keys for declassification token verification.
    ///
    /// When set, [`apply_declassification_token`](Self::apply_declassification_token)
    /// verifies token signatures against these keys before recording the
    /// declass scope. Supports key rotation by accepting multiple keys.
    ///
    /// When no trusted keys are set (the default), token application is
    /// REFUSED outright — fail-closed; see the body of
    /// `apply_declassification_token`. (This doc previously claimed a
    /// permissive backward-compatibility default the code does not have.)
    ///
    /// This key set is what the North Star means by "a governor": a
    /// principal holding a key configured here. It is configuration, not
    /// something any agent-reachable path may write.
    #[cfg(feature = "crypto")]
    pub fn set_trusted_keys(&mut self, keys: Vec<[u8; 32]>) {
        self.trusted_public_keys = keys;
    }

    /// Apply a cryptographically signed declassification token to a flow graph node.
    ///
    /// This is the secure path for declassification. The token must carry a
    /// valid Ed25519 signature from one of the kernel's trusted public keys
    /// (set via [`set_trusted_keys`](Self::set_trusted_keys)).
    ///
    /// If trusted keys are configured, the token's signature is verified
    /// before applying. If no trusted keys are configured, the token is
    /// REFUSED — fail-closed; there is no unsigned fallback.
    ///
    /// Returns `Err(DenyReason::InvalidDeclassification)` if trusted keys
    /// are set and signature verification fails.
    ///
    /// Returns `Ok(TokenApplyResult)` on success (or if the token was
    /// expired / precondition unmet — those are non-error rejections).
    #[cfg(feature = "crypto")]
    pub fn apply_declassification_token(
        &mut self,
        token: &portcullis_core::declassify::DeclassificationToken,
    ) -> Result<portcullis_core::declassify::TokenApplyResult, DenyReason> {
        let now = chrono::Utc::now().timestamp() as u64;

        // Fail-closed (most-paranoid #3): declassification weakens information-flow
        // labels, so it MUST be cryptographically authorized. With no trusted keys
        // configured there is no authority to verify against, so refuse outright
        // rather than applying the token unsigned.
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
        // One-shot (HC-6): the deterministic Ed25519 signature identifies exactly
        // one authorization. Its burn id is a 32-byte SHA-256 over the signature —
        // the width the SHARED `FlowGraph::release_burn_ledger` uses so the keyless
        // k-of-n memory path burns against the same ledger (Phase 4). Already
        // exercised ⇒ refuse with the dedicated replay verdict, BEFORE recording
        // any scope — a replayed token must not re-run the application.
        let burn_id = release_burn_id(&token.signature);
        if self.flow_graph.is_release_burned(&burn_id) {
            return Err(DenyReason::DeclassificationReplayed {
                target_node: token.target_node_id.to_string(),
            });
        }
        let key_refs: Vec<&[u8]> = self
            .trusted_public_keys
            .iter()
            .map(|k| k.as_slice())
            .collect();
        let result = self.flow_graph.apply_token_verified(token, &key_refs, now);
        if matches!(
            result,
            portcullis_core::declassify::TokenApplyResult::InvalidSignature
        ) {
            return Err(DenyReason::InvalidDeclassification {
                detail: "token signature verification failed — not signed by any trusted key"
                    .to_string(),
            });
        }
        // Burn only on success: an expired / precondition-unmet / node-not-found
        // token did not exercise its authority and stays usable once the
        // obstacle clears. This is the machine spec's `runD` semantics
        // (capability-primitive Spike/Declassify.lean: spend on release, never
        // on refusal), enforced live.
        if matches!(
            result,
            portcullis_core::declassify::TokenApplyResult::Applied { .. }
        ) {
            self.flow_graph.burn_release(burn_id);
        }
        Ok(result)
    }
}
