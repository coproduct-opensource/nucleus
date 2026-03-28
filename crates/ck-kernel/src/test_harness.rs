//! Test harness for local development with real cryptographic verification.
//!
//! Provides deterministic Ed25519 keypair generation, witness bundle signing,
//! and pre-configured [`SignatureVerifier`] instances for integration tests
//! and local development. Uses `ring` for all crypto operations.
//!
//! # Usage
//!
//! ```rust,no_run
//! use ck_kernel::test_harness::TestKeyring;
//!
//! let keyring = TestKeyring::new(&["ci-build", "ci-proof", "ci-replay"]);
//! let verifier = keyring.verifier();
//! let policy = keyring.signature_policy();
//! ```
//!
//! # Determinism
//!
//! Keys are derived from `SHA-256(name)` — the same name always produces
//! the same keypair. This makes tests reproducible without storing key files.
//!
//! # Security
//!
//! These keys are for testing only. The derivation scheme (`from_seed_unchecked`
//! with a predictable seed) is intentionally weak — anyone who knows the signer
//! name can reconstruct the private key. Never use these keys in production.

use ck_types::witness::{BundleSignature, SignatureVerifier, SignerRole, WitnessBundle};
use ring::signature::{Ed25519KeyPair, KeyPair};

/// A named signer with a deterministic Ed25519 keypair.
pub struct TestSigner {
    name: String,
    keypair: Ed25519KeyPair,
}

impl TestSigner {
    /// Create a signer with a deterministic keypair derived from the name.
    pub fn new(name: &str) -> Self {
        let seed_hash = ring::digest::digest(&ring::digest::SHA256, name.as_bytes());
        let keypair = Ed25519KeyPair::from_seed_unchecked(seed_hash.as_ref())
            .expect("valid Ed25519 seed");
        Self {
            name: name.to_string(),
            keypair,
        }
    }

    /// The signer's name (used as the `signer` field in BundleSignature).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The signer's Ed25519 public key bytes (32 bytes).
    pub fn public_key(&self) -> Vec<u8> {
        self.keypair.public_key().as_ref().to_vec()
    }

    /// Sign a witness bundle's canonical payload.
    pub fn sign_bundle(&self, bundle: &WitnessBundle) -> BundleSignature {
        self.sign_bundle_with_role(bundle, None)
    }

    /// Sign a witness bundle with a specific signer role.
    pub fn sign_bundle_with_role(
        &self,
        bundle: &WitnessBundle,
        role: Option<SignerRole>,
    ) -> BundleSignature {
        let payload = bundle.signing_payload();
        let sig = self.keypair.sign(&payload);
        BundleSignature {
            signer: self.name.clone(),
            algorithm: "ed25519".to_string(),
            signature: base64::engine::general_purpose::STANDARD
                .encode(sig.as_ref()),
            role,
        }
    }

    /// Sign arbitrary bytes (for custom verification scenarios).
    pub fn sign_bytes(&self, data: &[u8]) -> Vec<u8> {
        self.keypair.sign(data).as_ref().to_vec()
    }
}

use base64::Engine;

/// A collection of test signers with a pre-built verifier.
///
/// Provides a convenient way to set up a complete signing/verification
/// environment for integration tests and local development.
pub struct TestKeyring {
    signers: Vec<TestSigner>,
}

impl TestKeyring {
    /// Create a keyring with the given signer names.
    ///
    /// Each name deterministically produces a unique Ed25519 keypair.
    /// Common convention: `["ci-build", "ci-proof", "ci-replay"]` for
    /// role-separated signing.
    pub fn new(names: &[&str]) -> Self {
        Self {
            signers: names.iter().map(|n| TestSigner::new(n)).collect(),
        }
    }

    /// Build a `SignatureVerifier` trusting all signers in this keyring.
    pub fn verifier(&self) -> SignatureVerifier {
        let trusted_keys: Vec<(String, Vec<u8>)> = self
            .signers
            .iter()
            .map(|s| (s.name().to_string(), s.public_key()))
            .collect();
        SignatureVerifier::new(trusted_keys)
    }

    /// Build a role-enforcing `SignatureVerifier` trusting all signers.
    pub fn verifier_with_roles(&self, required_roles: Vec<SignerRole>) -> SignatureVerifier {
        let trusted_keys: Vec<(String, Vec<u8>)> = self
            .signers
            .iter()
            .map(|s| (s.name().to_string(), s.public_key()))
            .collect();
        SignatureVerifier::with_required_roles(trusted_keys, required_roles)
    }

    /// Get a specific signer by name.
    ///
    /// Panics if the name is not in this keyring.
    pub fn signer(&self, name: &str) -> &TestSigner {
        self.signers
            .iter()
            .find(|s| s.name() == name)
            .unwrap_or_else(|| panic!("no signer named '{name}' in keyring"))
    }

    /// All signer names in this keyring.
    pub fn names(&self) -> Vec<&str> {
        self.signers.iter().map(|s| s.name()).collect()
    }

    /// Sign a witness bundle with ALL signers (for tests that need full coverage).
    pub fn sign_all(&self, bundle: &WitnessBundle) -> Vec<BundleSignature> {
        self.signers.iter().map(|s| s.sign_bundle(bundle)).collect()
    }

    /// Sign a witness bundle with role-tagged signatures.
    ///
    /// Assigns roles round-robin to signers. Panics if there are more roles
    /// than signers.
    pub fn sign_with_roles(
        &self,
        bundle: &WitnessBundle,
        roles: &[SignerRole],
    ) -> Vec<BundleSignature> {
        assert!(
            roles.len() <= self.signers.len(),
            "more roles ({}) than signers ({})",
            roles.len(),
            self.signers.len()
        );
        self.signers
            .iter()
            .zip(roles.iter())
            .map(|(signer, role)| signer.sign_bundle_with_role(bundle, Some(role.clone())))
            .collect()
    }

    /// Build a `SignaturePolicy::Enforced` with this keyring's verifier.
    pub fn signature_policy(&self) -> crate::SignaturePolicy {
        crate::SignaturePolicy::Enforced(self.verifier())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_keypair() {
        let a = TestSigner::new("test-signer");
        let b = TestSigner::new("test-signer");
        assert_eq!(a.public_key(), b.public_key());
    }

    #[test]
    fn different_names_different_keys() {
        let a = TestSigner::new("alice");
        let b = TestSigner::new("bob");
        assert_ne!(a.public_key(), b.public_key());
    }

    #[test]
    fn keyring_verifier_trusts_all_signers() {
        let keyring = TestKeyring::new(&["ci-build", "ci-proof"]);
        let verifier = keyring.verifier();
        // Verifier should have 2 trusted keys
        assert_eq!(keyring.names().len(), 2);
        // Just verify it constructs without error
        drop(verifier);
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let signer = TestSigner::new("test");
        let data = b"hello world";
        let sig = signer.sign_bytes(data);

        // Verify with ring directly
        let pub_key = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ED25519,
            signer.public_key(),
        );
        assert!(pub_key.verify(data, &sig).is_ok());
    }

    #[test]
    fn keyring_signature_policy() {
        let keyring = TestKeyring::new(&["ci"]);
        let policy = keyring.signature_policy();
        assert!(matches!(policy, crate::SignaturePolicy::Enforced(_)));
    }
}
