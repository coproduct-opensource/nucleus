//! # nucleus-node-binding
//!
//! A signed binding layer that unifies an agent's **transport identity**
//! (an iroh `NodeId`, i.e. a 32-byte ed25519 transport public key) with its
//! **passport principal** (the subject the agent is known by in an attestation
//! / identity system). The goal it serves is "dial an agent by its proven
//! identity": given a binding, a verifier can be confident that a particular
//! passport principal vouches for control of a particular transport key.
//!
//! ## Scope — read this carefully
//!
//! A [`NodeBinding`] asserts exactly one thing:
//!
//! > **"this passport controls this transport key"**
//!
//! It does **NOT** assert that the agent is well-behaved, attested,
//! sandboxed, or otherwise trustworthy. Merely possessing a `NodeId` proves
//! control of a *transport key*, nothing more. Binding the `NodeId` to a
//! passport principal requires a *signed statement* (this struct) where the
//! passport key vouches for the `NodeId` — co-location or self-assertion is
//! not enough. Attested properties (capabilities, behaviour, policy
//! compliance) live in other layers and are out of scope here.
//!
//! ## Invariants
//!
//! - **Fail-closed.** A forged, tampered, unsigned, or wrong-key binding
//!   verifies to `Err(..)` and contributes no trust. There is no
//!   success-by-default path.
//! - **No key smuggling.** Verification trusts a passport public key that the
//!   **caller** supplies, keyed by the principal in their own identity system.
//!   The binding message carries no passport public key that verification
//!   trusts — an attacker cannot ship their own key inside the binding.
//! - **Domain separation.** The signed bytes are prefixed with
//!   `b"nucleus-node-binding/v1\n:"`, so a passport signature minted for some
//!   other purpose cannot be replayed as a node binding, and vice versa.
//! - **Pure.** This slice depends only on `ed25519-dalek` (workspace-pinned)
//!   plus `serde`/`hex`/`thiserror`. There is **no** iroh / iroh-gossip / QUIC
//!   dependency. The `NodeId <-> [u8; 32]` conversions are a later,
//!   feature-gated slice.
//!
//! ## Example
//!
//! ```
//! use ed25519_dalek::SigningKey;
//! use nucleus_node_binding::{sign_binding, verify_binding};
//!
//! // The agent's passport signing key (lives in the identity system).
//! let passport_sk = SigningKey::from_bytes(&[7u8; 32]);
//! let passport_pk = passport_sk.verifying_key().to_bytes();
//!
//! // The agent's transport key (an iroh NodeId is exactly these 32 bytes).
//! let node_id = [42u8; 32];
//!
//! let binding = sign_binding(&node_id, "spiffe://example/agent-x", &passport_sk);
//!
//! // A verifier that already trusts `passport_pk` (keyed by the principal in
//! // its own system) confirms the passport vouches for this transport key.
//! verify_binding(&binding, &passport_pk).expect("binding verifies");
//! ```

use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};

/// Domain-separation prefix for the signed binding message.
///
/// The trailing `\n:` keeps the version token unambiguous and delimits the
/// prefix from the payload. Future protocol versions use `/v2`, `/v3`, ...,
/// so a signature minted under one version never verifies under another.
const DOMAIN_PREFIX: &[u8] = b"nucleus-node-binding/v1\n:";

/// A signed statement that a passport principal controls a transport key.
///
/// The struct deliberately carries **only** the bound data plus the
/// signature — never a passport public key that verification trusts. The
/// caller supplies the trusted key to [`verify_binding`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeBinding {
    /// 32-byte ed25519 transport public key (an iroh `NodeId`).
    pub node_id: [u8; 32],

    /// Principal identifier (e.g. SPIFFE subject, agent name, or any string)
    /// the passport is known by in the verifier's identity system.
    pub principal: String,

    /// Ed25519 signature over [`binding_message`]`(node_id, principal)`,
    /// produced by the passport signing key. Serialized as hex on the wire
    /// (serde cannot derive `[u8; 64]` directly).
    #[serde(with = "sig_hex")]
    pub sig: [u8; 64],
}

/// Compute the domain-separated message that is signed for a binding.
///
/// Framing (all concatenated, in order):
/// 1. Domain prefix `b"nucleus-node-binding/v1\n:"`.
/// 2. The 32-byte `node_id` (raw bytes).
/// 3. A single `b":"` separator.
/// 4. The `principal` string (UTF-8 bytes, as-is; it terminates the message).
///
/// This is a total, deterministic function of its inputs: the same
/// `(node_id, principal)` pair always yields identical bytes.
pub fn binding_message(node_id: &[u8; 32], principal: &str) -> Vec<u8> {
    let mut msg = Vec::with_capacity(DOMAIN_PREFIX.len() + 32 + 1 + principal.len());
    msg.extend_from_slice(DOMAIN_PREFIX);
    msg.extend_from_slice(node_id);
    msg.push(b':');
    msg.extend_from_slice(principal.as_bytes());
    msg
}

/// Sign a binding with the supplied passport signing key.
///
/// Intended for agents minting their own bindings (and for tests). The
/// resulting [`NodeBinding`] asserts that this passport controls `node_id` —
/// nothing about the agent's behaviour or attested properties.
pub fn sign_binding(
    node_id: &[u8; 32],
    principal: &str,
    passport_signing_key: &ed25519_dalek::SigningKey,
) -> NodeBinding {
    let msg = binding_message(node_id, principal);
    let sig = passport_signing_key.sign(&msg);
    NodeBinding {
        node_id: *node_id,
        principal: principal.to_string(),
        sig: sig.to_bytes(),
    }
}

/// Verify a binding against a **caller-supplied trusted passport public key**.
///
/// The caller keys `trusted_passport_pubkey` by the principal in their own
/// identity system; the binding itself contributes no trusted key. Returns
/// `Ok(())` only when the signature over the domain-separated
/// [`binding_message`] verifies under that key.
///
/// Fail-closed: a forged, tampered, unsigned, or wrong-key binding returns
/// `Err(..)`.
#[must_use = "the verification result must be checked; a dropped `Err` silently accepts an unverified binding"]
pub fn verify_binding(
    binding: &NodeBinding,
    trusted_passport_pubkey: &[u8; 32],
) -> Result<(), BindingError> {
    let msg = binding_message(&binding.node_id, &binding.principal);
    let vk = ed25519_dalek::VerifyingKey::from_bytes(trusted_passport_pubkey)
        .map_err(|e| BindingError::InvalidKey(e.to_string()))?;
    let sig = ed25519_dalek::Signature::from_bytes(&binding.sig);
    vk.verify_strict(&msg, &sig)
        .map_err(|e| BindingError::SignatureMismatch(e.to_string()))?;
    Ok(())
}

/// Errors returned by [`verify_binding`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BindingError {
    /// The supplied trusted passport public key bytes are not a valid
    /// ed25519 point.
    #[error("verifying key invalid: {0}")]
    InvalidKey(String),

    /// The signature did not verify against the trusted key over the
    /// domain-separated binding message.
    #[error("binding signature did not verify: {0}")]
    SignatureMismatch(String),
}

/// Serde with-module: encode the `[u8; 64]` signature as a hex string.
mod sig_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(sig: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(sig))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let hex_str = String::deserialize(d)?;
        let bytes = hex::decode(&hex_str)
            .map_err(|e| serde::de::Error::custom(format!("hex decode failed: {e}")))?;
        let sig: [u8; 64] = bytes.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!(
                "signature must be exactly 64 bytes, got {}",
                v.len()
            ))
        })?;
        Ok(sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn test_sk() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
    }

    fn test_sk_alt() -> SigningKey {
        SigningKey::from_bytes(&[99u8; 32])
    }

    // TEST 1: round-trip sign -> verify with the correct key returns Ok.
    #[test]
    fn binding_round_trip_verifies() {
        let sk = test_sk();
        let vk: [u8; 32] = sk.verifying_key().to_bytes();

        let node_id = [123u8; 32];
        let principal = "spiffe://example/agent-x";

        let binding = sign_binding(&node_id, principal, &sk);
        assert_eq!(binding.node_id, node_id);
        assert_eq!(binding.principal, principal);

        verify_binding(&binding, &vk).expect("freshly signed binding must verify");
    }

    // TEST 2: tampering the node_id fails verification (fail-closed).
    #[test]
    fn tampered_node_id_fails_verify() {
        let sk = test_sk();
        let vk: [u8; 32] = sk.verifying_key().to_bytes();

        let mut binding = sign_binding(&[1u8; 32], "agent", &sk);
        binding.node_id[0] ^= 0xFF;

        assert!(verify_binding(&binding, &vk).is_err());
    }

    // TEST 3: rewriting the principal fails verification (fail-closed).
    #[test]
    fn tampered_principal_fails_verify() {
        let sk = test_sk();
        let vk: [u8; 32] = sk.verifying_key().to_bytes();

        let mut binding = sign_binding(&[2u8; 32], "alice", &sk);
        binding.principal = "bob".to_string();

        assert!(verify_binding(&binding, &vk).is_err());
    }

    // TEST 4: tampering the signature fails verification (fail-closed).
    #[test]
    fn tampered_signature_fails_verify() {
        let sk = test_sk();
        let vk: [u8; 32] = sk.verifying_key().to_bytes();

        let mut binding = sign_binding(&[3u8; 32], "agent", &sk);
        binding.sig[0] ^= 0xFF;

        assert!(verify_binding(&binding, &vk).is_err());
    }

    // TEST 5: verifying against the wrong passport public key fails.
    #[test]
    fn wrong_passport_pubkey_fails_verify() {
        let sk_a = test_sk();
        let sk_b = test_sk_alt();
        let vk_b: [u8; 32] = sk_b.verifying_key().to_bytes();

        let binding = sign_binding(&[4u8; 32], "agent", &sk_a);

        assert!(verify_binding(&binding, &vk_b).is_err());
    }

    // TEST 6: NO KEY SMUGGLING — a binding claiming principal "principal-a"
    // but actually signed by attacker key B must fail when the verifier
    // checks it against the genuine A's trusted pubkey.
    #[test]
    fn key_smuggling_attempt_fails() {
        let sk_a = test_sk();
        let sk_b = test_sk_alt();
        let vk_a: [u8; 32] = sk_a.verifying_key().to_bytes();

        let binding = sign_binding(&[5u8; 32], "principal-a", &sk_b);

        assert!(verify_binding(&binding, &vk_a).is_err());
    }

    // TEST 7: DOMAIN SEPARATION — a signature over the raw payload WITHOUT
    // the domain prefix must not verify as a binding.
    #[test]
    fn domain_separation_signature_without_prefix_fails() {
        let sk = test_sk();
        let vk: [u8; 32] = sk.verifying_key().to_bytes();

        let node_id = [6u8; 32];
        let principal = "test-agent";

        let mut attacker_msg = Vec::new();
        attacker_msg.extend_from_slice(&node_id);
        attacker_msg.extend_from_slice(principal.as_bytes());
        let attacker_sig = sk.sign(&attacker_msg);

        let fake_binding = NodeBinding {
            node_id,
            principal: principal.to_string(),
            sig: attacker_sig.to_bytes(),
        };

        assert!(verify_binding(&fake_binding, &vk).is_err());
    }

    // TEST 8: serde round-trip preserves the binding exactly.
    #[test]
    fn binding_serde_round_trip() {
        let sk = test_sk();
        let binding = sign_binding(&[7u8; 32], "serde-test", &sk);

        let json = serde_json::to_string(&binding).expect("serialize");
        let restored: NodeBinding = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(binding, restored);
        // The signature travels as hex on the wire.
        assert!(json.contains(&hex::encode(binding.sig)));

        // A deserialized binding still verifies under the genuine key.
        let vk: [u8; 32] = sk.verifying_key().to_bytes();
        verify_binding(&restored, &vk).expect("round-tripped binding must verify");
    }

    // TEST 9: binding_message is deterministic and domain-tagged.
    #[test]
    fn binding_message_is_deterministic() {
        let node_id = [77u8; 32];
        let principal = "agent-determinism";

        let msg1 = binding_message(&node_id, principal);
        let msg2 = binding_message(&node_id, principal);

        assert_eq!(msg1, msg2);
        assert!(msg1.starts_with(b"nucleus-node-binding/v1\n:"));
    }
}
