//! Ed25519 signing and verification for declassification tokens.
//!
//! Declassification tokens permit controlled label downgrading on specific
//! flow graph nodes. Without cryptographic verification, any code that can
//! construct a `DeclassificationToken` can declassify arbitrary nodes.
//!
//! This module provides:
//! - `sign_token()` — signs a token's canonical bytes with an Ed25519 key
//! - `verify_token()` — verifies the signature against a trusted public key
//!
//! The signing/verification follows the same pattern as `receipt_sign.rs`.

#[cfg(feature = "crypto")]
use ring::signature::{self, Ed25519KeyPair, UnparsedPublicKey};

use portcullis_core::declassify::DeclassificationToken;
use portcullis_core::receipt::SignatureError;

/// Sign a declassification token with an Ed25519 key.
///
/// Mutates the token's signature field in place. The signature covers
/// all security-relevant fields via `canonical_bytes()`.
#[cfg(feature = "crypto")]
pub fn sign_token(token: &mut DeclassificationToken, signing_key: &Ed25519KeyPair) {
    let content = token.canonical_bytes();
    let sig = signing_key.sign(&content);
    let sig_bytes: [u8; 64] = sig
        .as_ref()
        .try_into()
        .expect("Ed25519 signature is 64 bytes");
    token.set_signature(sig_bytes);
}

/// Verify a declassification token's Ed25519 signature against a public key.
///
/// Returns `Ok(())` if the signature is valid, or an appropriate error.
#[cfg(feature = "crypto")]
pub fn verify_token(
    token: &DeclassificationToken,
    public_key_bytes: &[u8],
) -> Result<(), SignatureError> {
    if !token.is_signed() {
        return Err(SignatureError::Unsigned);
    }

    let content = token.canonical_bytes();
    let public_key = UnparsedPublicKey::new(&signature::ED25519, public_key_bytes);

    public_key
        .verify(&content, &token.signature)
        .map_err(|_| SignatureError::InvalidSignature)
}

/// Verify a declassification token against a set of trusted public keys.
///
/// Returns `Ok(())` if the signature verifies against ANY of the trusted keys.
/// This supports key rotation: callers can provide both the current and
/// previous public keys.
///
/// Returns `Err(SignatureError::Unsigned)` if the token has no signature.
/// Returns `Err(SignatureError::InvalidSignature)` if no key matches.
#[cfg(feature = "crypto")]
pub fn verify_token_any_key(
    token: &DeclassificationToken,
    trusted_keys: &[&[u8]],
) -> Result<(), SignatureError> {
    if !token.is_signed() {
        return Err(SignatureError::Unsigned);
    }
    if trusted_keys.is_empty() {
        return Err(SignatureError::InvalidSignature);
    }
    for key in trusted_keys {
        if verify_token(token, key).is_ok() {
            return Ok(());
        }
    }
    Err(SignatureError::InvalidSignature)
}

#[cfg(test)]
#[cfg(feature = "crypto")]
mod tests {
    use super::*;
    use portcullis_core::declassify::{DeclassificationRule, DeclassifyAction};
    use portcullis_core::{IntegLevel, Operation};
    use ring::rand::SystemRandom;
    use ring::signature::KeyPair;

    fn test_key() -> Ed25519KeyPair {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    fn make_token() -> DeclassificationToken {
        DeclassificationToken::new(
            42,
            DeclassificationRule {
                action: DeclassifyAction::RaiseIntegrity {
                    from: IntegLevel::Adversarial,
                    to: IntegLevel::Untrusted,
                },
                justification: "Validated search results",
            },
            vec![Operation::WriteFiles, Operation::GitCommit],
            u64::MAX,
            "Curated API output".to_string(),
        )
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = test_key();
        let mut token = make_token();

        assert!(!token.is_signed());
        sign_token(&mut token, &key);
        assert!(token.is_signed());

        let public_key = key.public_key().as_ref();
        assert!(verify_token(&token, public_key).is_ok());
    }

    #[test]
    fn verify_rejects_unsigned() {
        let key = test_key();
        let token = make_token();

        assert!(!token.is_signed());
        let public_key = key.public_key().as_ref();
        assert_eq!(
            verify_token(&token, public_key),
            Err(SignatureError::Unsigned)
        );
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let sign_key = test_key();
        let wrong_key = test_key();
        let mut token = make_token();

        sign_token(&mut token, &sign_key);

        let wrong_public = wrong_key.public_key().as_ref();
        assert_eq!(
            verify_token(&token, wrong_public),
            Err(SignatureError::InvalidSignature)
        );
    }

    #[test]
    fn tampered_token_rejected() {
        let key = test_key();
        let mut token = make_token();
        sign_token(&mut token, &key);

        token.target_node_id = 999;

        let public_key = key.public_key().as_ref();
        assert_eq!(
            verify_token(&token, public_key),
            Err(SignatureError::InvalidSignature),
            "Tampering with target_node_id must invalidate signature"
        );
    }

    #[test]
    fn tampered_justification_rejected() {
        let key = test_key();
        let mut token = make_token();
        sign_token(&mut token, &key);

        token.justification = "malicious override".to_string();

        let public_key = key.public_key().as_ref();
        assert_eq!(
            verify_token(&token, public_key),
            Err(SignatureError::InvalidSignature),
            "Tampering with justification must invalidate signature"
        );
    }

    #[test]
    fn tampered_valid_until_rejected() {
        let key = test_key();
        let mut token = make_token();
        sign_token(&mut token, &key);

        token.valid_until = 1;

        let public_key = key.public_key().as_ref();
        assert_eq!(
            verify_token(&token, public_key),
            Err(SignatureError::InvalidSignature),
            "Tampering with valid_until must invalidate signature"
        );
    }

    #[test]
    fn verify_any_key_accepts_correct() {
        let key1 = test_key();
        let key2 = test_key();
        let mut token = make_token();
        sign_token(&mut token, &key1);

        let pk1 = key1.public_key().as_ref();
        let pk2 = key2.public_key().as_ref();

        assert!(verify_token_any_key(&token, &[pk2, pk1]).is_ok());
    }

    #[test]
    fn verify_any_key_rejects_none_matching() {
        let sign_key = test_key();
        let wrong1 = test_key();
        let wrong2 = test_key();
        let mut token = make_token();
        sign_token(&mut token, &sign_key);

        let wpk1 = wrong1.public_key().as_ref();
        let wpk2 = wrong2.public_key().as_ref();

        assert_eq!(
            verify_token_any_key(&token, &[wpk1, wpk2]),
            Err(SignatureError::InvalidSignature)
        );
    }

    #[test]
    fn verify_any_key_rejects_empty_keys() {
        let key = test_key();
        let mut token = make_token();
        sign_token(&mut token, &key);

        assert_eq!(
            verify_token_any_key(&token, &[]),
            Err(SignatureError::InvalidSignature)
        );
    }

    #[test]
    fn verify_any_key_rejects_unsigned() {
        let token = make_token();
        let key = test_key();
        let pk = key.public_key().as_ref();

        assert_eq!(
            verify_token_any_key(&token, &[pk]),
            Err(SignatureError::Unsigned)
        );
    }
}
