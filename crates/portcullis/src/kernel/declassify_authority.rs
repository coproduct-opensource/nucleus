//! The kernel's declassification authority surface: trusted-key configuration
//! and one-shot token application. Extracted from `kernel.rs` (line ratchet);
//! a CHILD module of `kernel`, so the impl reaches the kernel's private fields
//! (`trusted_public_keys`, `applied_declassifications`, `flow_graph`) without
//! widening their visibility.

use super::{DenyReason, Kernel};

#[cfg(feature = "crypto")]
impl Kernel {
    /// Set trusted Ed25519 public keys for declassification token verification.
    ///
    /// When set, [`apply_declassification_token`](Self::apply_declassification_token)
    /// verifies token signatures against these keys before applying label
    /// changes. Supports key rotation by accepting multiple keys.
    ///
    /// When no trusted keys are set (the default), unsigned declassification
    /// rules are applied without verification for backward compatibility.
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
    /// applied without verification (backward compatibility) with a warning.
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
        let graph = &mut self.flow_graph;

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
        // One-shot (HC-6): the deterministic Ed25519 signature identifies
        // exactly one authorization. Already exercised ⇒ refuse with the
        // dedicated replay verdict, BEFORE touching the flow graph — a replayed
        // token must not re-run any part of the application.
        if self.applied_declassifications.contains(&token.signature) {
            return Err(DenyReason::DeclassificationReplayed {
                target_node: token.target_node_id.to_string(),
            });
        }
        let key_refs: Vec<&[u8]> = self
            .trusted_public_keys
            .iter()
            .map(|k| k.as_slice())
            .collect();
        let result = graph.apply_token_verified(token, &key_refs, now);
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
            self.applied_declassifications.insert(token.signature);
        }
        Ok(result)
    }
}
