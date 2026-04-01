//! Ed25519 receipt signing and verification.
//!
//! Signs flow receipts so that downstream consumers (audit systems,
//! compliance dashboards) can verify that a receipt was produced by
//! a trusted kernel and has not been tampered with.
//!
//! The signing key is held by the kernel operator. The public key is
//! distributed to verifiers.

#[cfg(feature = "crypto")]
use ring::signature::{self, Ed25519KeyPair, UnparsedPublicKey};

use portcullis_core::receipt::{receipt_canonical_bytes, FlowReceipt, SignatureError};

/// Serialize receipt content to canonical bytes for signing.
///
/// Delegates to `portcullis_core::receipt::receipt_canonical_bytes()` —
/// the single source of truth for the canonical byte representation.
fn receipt_content_bytes(receipt: &FlowReceipt) -> Vec<u8> {
    receipt_canonical_bytes(receipt)
}

/// Compute the SHA-256 hash of a receipt's canonical content + signature.
///
/// This hash is the chain link — the next receipt includes it as `prev_hash`,
/// creating an append-only chain where deletion or reordering is detectable.
///
/// The hash covers the signed content AND the signature, so the chain
/// commits to the specific signed version of each receipt.
pub fn receipt_hash(receipt: &FlowReceipt) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(receipt_content_bytes(receipt));
    hasher.update(receipt.signature_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Sign a flow receipt with an Ed25519 key.
///
/// Mutates the receipt's signature field in place. The signature covers
/// all security-relevant fields in canonical byte order.
#[cfg(feature = "crypto")]
pub fn sign_receipt(receipt: &mut FlowReceipt, signing_key: &Ed25519KeyPair) {
    let content = receipt_content_bytes(receipt);
    let sig = signing_key.sign(&content);
    let sig_bytes: [u8; 64] = sig
        .as_ref()
        .try_into()
        .expect("Ed25519 signature is 64 bytes");
    receipt.set_signature(sig_bytes);
}

/// Verify a receipt's Ed25519 signature against a public key.
///
/// Returns `Ok(())` if the signature is valid, or an appropriate error.
#[cfg(feature = "crypto")]
pub fn verify_receipt(
    receipt: &FlowReceipt,
    public_key_bytes: &[u8],
) -> Result<(), SignatureError> {
    if !receipt.is_signed() {
        return Err(SignatureError::Unsigned);
    }

    let content = receipt_content_bytes(receipt);
    let public_key = UnparsedPublicKey::new(&signature::ED25519, public_key_bytes);

    public_key
        .verify(&content, receipt.signature_bytes())
        .map_err(|_| SignatureError::InvalidSignature)
}

#[cfg(test)]
#[cfg(feature = "crypto")]
mod tests {
    use super::*;
    use portcullis_core::flow::{FlowDenyReason, FlowNode, FlowVerdict, NodeKind, MAX_PARENTS};
    use portcullis_core::receipt::build_receipt;
    use portcullis_core::{
        AuthorityLevel, ConfLevel, Freshness, IFCLabel, IntegLevel, Operation, ProvenanceSet,
    };
    use ring::rand::SystemRandom;
    use ring::signature::KeyPair;

    fn test_key() -> Ed25519KeyPair {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    fn make_node(id: u64, kind: NodeKind, label: IFCLabel, op: Option<Operation>) -> FlowNode {
        FlowNode {
            id,
            kind,
            label,
            parent_count: 0,
            parents: [0; MAX_PARENTS],
            operation: op,
            sink_class: None,
            effect_kind: None,
        }
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = test_key();
        let label = IFCLabel::user_prompt(1000);
        let action = make_node(
            1,
            NodeKind::OutboundAction,
            label,
            Some(Operation::WriteFiles),
        );
        let mut receipt = build_receipt(&action, &[], FlowVerdict::Allow, 2000);

        assert!(!receipt.is_signed());
        sign_receipt(&mut receipt, &key);
        assert!(receipt.is_signed());

        let public_key = key.public_key().as_ref();
        assert!(verify_receipt(&receipt, public_key).is_ok());
    }

    #[test]
    fn verify_rejects_unsigned() {
        let key = test_key();
        let label = IFCLabel::user_prompt(1000);
        let action = make_node(
            1,
            NodeKind::OutboundAction,
            label,
            Some(Operation::WriteFiles),
        );
        let receipt = build_receipt(&action, &[], FlowVerdict::Allow, 2000);

        let public_key = key.public_key().as_ref();
        assert_eq!(
            verify_receipt(&receipt, public_key),
            Err(SignatureError::Unsigned)
        );
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let sign_key = test_key();
        let wrong_key = test_key();

        let label = IFCLabel::web_content(1000);
        let action = make_node(1, NodeKind::OutboundAction, label, Some(Operation::GitPush));
        let mut receipt = build_receipt(
            &action,
            &[],
            FlowVerdict::Deny(FlowDenyReason::AuthorityEscalation),
            2000,
        );

        sign_receipt(&mut receipt, &sign_key);

        let wrong_public = wrong_key.public_key().as_ref();
        assert_eq!(
            verify_receipt(&receipt, wrong_public),
            Err(SignatureError::InvalidSignature)
        );
    }

    #[test]
    fn signed_receipt_display_no_warning() {
        let key = test_key();
        let label = IFCLabel::user_prompt(1000);
        let action = make_node(
            1,
            NodeKind::OutboundAction,
            label,
            Some(Operation::WriteFiles),
        );
        let mut receipt = build_receipt(&action, &[], FlowVerdict::Allow, 2000);
        sign_receipt(&mut receipt, &key);

        let display = receipt.display_chain();
        assert!(!display.contains("UNSIGNED"));
    }

    #[test]
    fn sign_receipt_with_ancestors() {
        let key = test_key();
        let now = 1000;
        let web = make_node(10, NodeKind::WebContent, IFCLabel::web_content(now), None);
        let file = make_node(
            20,
            NodeKind::FileRead,
            IFCLabel {
                confidentiality: ConfLevel::Internal,
                integrity: IntegLevel::Trusted,
                provenance: ProvenanceSet::USER,
                freshness: Freshness {
                    observed_at: now,
                    ttl_secs: 0,
                },
                authority: AuthorityLevel::Directive,
                derivation: portcullis_core::DerivationClass::Deterministic,
            },
            None,
        );
        let action = make_node(
            30,
            NodeKind::OutboundAction,
            IFCLabel::web_content(now),
            Some(Operation::CreatePr),
        );

        let mut receipt = build_receipt(
            &action,
            &[&web, &file],
            FlowVerdict::Deny(FlowDenyReason::AuthorityEscalation),
            now + 10,
        );

        sign_receipt(&mut receipt, &key);
        assert!(receipt.is_signed());

        let public_key = key.public_key().as_ref();
        assert!(verify_receipt(&receipt, public_key).is_ok());
    }

    #[test]
    fn hash_chain_integrity() {
        let key = test_key();
        let now = 1000;

        // Receipt 1: first in chain (prev_hash = zeros)
        let action1 = make_node(
            1,
            NodeKind::FileRead,
            IFCLabel::user_prompt(now),
            Some(Operation::ReadFiles),
        );
        let mut r1 = build_receipt(&action1, &[], FlowVerdict::Allow, now);
        sign_receipt(&mut r1, &key);
        let h1 = receipt_hash(&r1);

        // Receipt 2: chained to receipt 1
        let action2 = make_node(
            2,
            NodeKind::WebContent,
            IFCLabel::web_content(now + 1),
            Some(Operation::WebFetch),
        );
        let mut r2 = build_receipt(&action2, &[], FlowVerdict::Allow, now + 1);
        r2.set_prev_hash(h1);
        sign_receipt(&mut r2, &key);
        let h2 = receipt_hash(&r2);

        // Receipt 3: chained to receipt 2
        let action3 = make_node(
            3,
            NodeKind::OutboundAction,
            IFCLabel::web_content(now + 2),
            Some(Operation::WriteFiles),
        );
        let mut r3 = build_receipt(
            &action3,
            &[&action1, &action2],
            FlowVerdict::Deny(FlowDenyReason::AuthorityEscalation),
            now + 2,
        );
        r3.set_prev_hash(h2);
        sign_receipt(&mut r3, &key);

        // All receipts verify
        let pk = key.public_key().as_ref();
        assert!(verify_receipt(&r1, pk).is_ok());
        assert!(verify_receipt(&r2, pk).is_ok());
        assert!(verify_receipt(&r3, pk).is_ok());

        // Chain links are correct
        assert_eq!(r1.prev_hash(), &[0; 32]); // first in chain
        assert_eq!(r2.prev_hash(), &h1);
        assert_eq!(r3.prev_hash(), &h2);

        // Hashes are unique
        assert_ne!(h1, h2);
        assert_ne!(h2, receipt_hash(&r3));
    }

    #[test]
    fn tampered_chain_detected() {
        let key = test_key();
        let now = 1000;

        let action1 = make_node(1, NodeKind::FileRead, IFCLabel::user_prompt(now), None);
        let mut r1 = build_receipt(&action1, &[], FlowVerdict::Allow, now);
        sign_receipt(&mut r1, &key);
        let h1 = receipt_hash(&r1);

        // Receipt 2 links to receipt 1
        let action2 = make_node(
            2,
            NodeKind::OutboundAction,
            IFCLabel::user_prompt(now),
            None,
        );
        let mut r2 = build_receipt(&action2, &[], FlowVerdict::Allow, now + 1);
        r2.set_prev_hash(h1);
        sign_receipt(&mut r2, &key);

        // Tamper: change prev_hash to skip receipt 1
        // This invalidates the signature
        let mut tampered = r2.clone();
        tampered.set_prev_hash([0; 32]);
        let pk = key.public_key().as_ref();
        assert_eq!(
            verify_receipt(&tampered, pk),
            Err(SignatureError::InvalidSignature),
            "Tampering with prev_hash must invalidate signature"
        );
    }

    #[test]
    fn verify_rejects_forged_signature() {
        let key = test_key();
        let label = IFCLabel::user_prompt(1000);
        let action = make_node(
            1,
            NodeKind::OutboundAction,
            label,
            Some(Operation::WriteFiles),
        );
        let mut receipt = build_receipt(&action, &[], FlowVerdict::Allow, 2000);

        // Set a fake signature (non-zero but not valid Ed25519)
        receipt.set_signature([0xDE; 64]);
        assert!(receipt.is_signed());

        let pk = key.public_key().as_ref();
        assert_eq!(
            verify_receipt(&receipt, pk),
            Err(SignatureError::InvalidSignature),
            "Forged signature bytes must be rejected"
        );
    }

    #[test]
    fn verify_rejects_tampered_chain_id() {
        let key = test_key();
        let label = IFCLabel::user_prompt(1000);
        let action = make_node(
            1,
            NodeKind::OutboundAction,
            label,
            Some(Operation::WriteFiles),
        );
        let mut receipt = build_receipt(&action, &[], FlowVerdict::Allow, 2000);
        receipt.set_chain_id([0x42; 32]);
        sign_receipt(&mut receipt, &key);

        // Tamper with chain_id after signing
        let mut tampered = receipt.clone();
        tampered.set_chain_id([0xFF; 32]);
        let pk = key.public_key().as_ref();
        assert_eq!(
            verify_receipt(&tampered, pk),
            Err(SignatureError::InvalidSignature),
            "Tampering with chain_id must invalidate signature"
        );
    }
}
