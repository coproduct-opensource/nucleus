//! Remote attestation — binding enforcement evidence to platform measurements.
//!
//! An `AttestationReport` binds three hashes to prove that a specific
//! verified kernel configuration produced a specific receipt chain:
//!
//! 1. **Kernel config hash** — SHA-256 of the PermissionLattice + policy
//! 2. **Receipt chain hash** — SHA-256 head of the receipt chain
//! 3. **Proof hash** — SHA-256 of the Lean/Kani proof artifacts
//!
//! In a hardware TEE (Firecracker on AMD SEV-SNP or Intel TDX), these
//! hashes are extended into the platform measurement register, creating
//! a hardware-rooted chain of trust. On workstations, the report is
//! self-signed (software attestation) — useful for audit but not
//! hardware-rooted.
//!
//! ## Verification
//!
//! A verifier checks:
//! 1. Report signature is valid (Ed25519)
//! 2. Kernel config hash matches the expected policy
//! 3. Receipt chain hash matches the receipt file
//! 4. Timestamp is fresh (within acceptable window)

use sha2::{Digest, Sha256};

/// An attestation report binding enforcement evidence to platform state.
#[derive(Debug, Clone)]
pub struct AttestationReport {
    /// SHA-256 of the kernel configuration (PermissionLattice + policy).
    pub kernel_config_hash: [u8; 32],
    /// SHA-256 head of the receipt chain.
    pub receipt_chain_hash: [u8; 32],
    /// SHA-256 of the proof artifacts (Lean + Kani).
    pub proof_hash: [u8; 32],
    /// Unix timestamp when the report was generated.
    pub timestamp: u64,
    /// Platform type that generated this report.
    pub platform: AttestationPlatform,
    /// Ed25519 signature over the canonical report content.
    pub signature: [u8; 64],
}

/// Platform that generated the attestation report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationPlatform {
    /// Software-only attestation (self-signed, no hardware root).
    /// Useful for audit trail but trusts the host.
    Software,
    /// AMD SEV-SNP with Firecracker.
    AmdSevSnp,
    /// Intel TDX with Firecracker.
    IntelTdx,
}

impl AttestationReport {
    /// Compute the canonical content bytes for signing/verification.
    pub fn content_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(b"nucleus-attestation-v1\n");
        buf.extend_from_slice(&self.kernel_config_hash);
        buf.extend_from_slice(&self.receipt_chain_hash);
        buf.extend_from_slice(&self.proof_hash);
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.push(self.platform as u8);
        buf
    }

    /// Create an unsigned report.
    pub fn new(
        kernel_config_hash: [u8; 32],
        receipt_chain_hash: [u8; 32],
        proof_hash: [u8; 32],
        timestamp: u64,
        platform: AttestationPlatform,
    ) -> Self {
        Self {
            kernel_config_hash,
            receipt_chain_hash,
            proof_hash,
            timestamp,
            platform,
            signature: [0; 64],
        }
    }

    /// Check if the report is signed.
    pub fn is_signed(&self) -> bool {
        self.signature != [0; 64]
    }

    /// Check if the report is fresh (within the given window in seconds).
    pub fn is_fresh(&self, now: u64, max_age_secs: u64) -> bool {
        now <= self.timestamp + max_age_secs
    }

    /// Set the signature.
    pub fn set_signature(&mut self, sig: [u8; 64]) {
        self.signature = sig;
    }
}

/// Compute a SHA-256 hash of arbitrary bytes (for config/proof hashing).
pub fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Verification result for an attestation report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyResult {
    /// Report is valid.
    Valid,
    /// Report signature is invalid or missing.
    InvalidSignature,
    /// Report is stale (timestamp too old).
    Stale {
        /// Report age in seconds.
        age_secs: u64,
    },
    /// Kernel config hash doesn't match expected.
    ConfigMismatch,
    /// Receipt chain hash doesn't match expected.
    ReceiptMismatch,
}

/// Verify an attestation report against expected values.
///
/// Does NOT verify the Ed25519 signature (that requires ring, which
/// is in portcullis not portcullis-core). This checks structural validity.
pub fn verify_report(
    report: &AttestationReport,
    expected_config_hash: &[u8; 32],
    expected_receipt_hash: &[u8; 32],
    now: u64,
    max_age_secs: u64,
) -> VerifyResult {
    if report.kernel_config_hash != *expected_config_hash {
        return VerifyResult::ConfigMismatch;
    }
    if report.receipt_chain_hash != *expected_receipt_hash {
        return VerifyResult::ReceiptMismatch;
    }
    if !report.is_fresh(now, max_age_secs) {
        return VerifyResult::Stale {
            age_secs: now.saturating_sub(report.timestamp),
        };
    }
    if !report.is_signed() {
        return VerifyResult::InvalidSignature;
    }
    VerifyResult::Valid
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_report() -> AttestationReport {
        AttestationReport::new(
            sha256_hash(b"test-config"),
            sha256_hash(b"test-receipts"),
            sha256_hash(b"test-proofs"),
            1000,
            AttestationPlatform::Software,
        )
    }

    #[test]
    fn unsigned_report_detected() {
        let report = test_report();
        assert!(!report.is_signed());
    }

    #[test]
    fn freshness_check() {
        let report = test_report();
        assert!(report.is_fresh(1000, 3600)); // same time
        assert!(report.is_fresh(4599, 3600)); // within window
        assert!(!report.is_fresh(4601, 3600)); // expired
    }

    #[test]
    fn verify_valid_report() {
        let mut report = test_report();
        report.set_signature([1; 64]); // fake sig for testing

        let result = verify_report(
            &report,
            &sha256_hash(b"test-config"),
            &sha256_hash(b"test-receipts"),
            1000,
            3600,
        );
        assert_eq!(result, VerifyResult::Valid);
    }

    #[test]
    fn verify_config_mismatch() {
        let mut report = test_report();
        report.set_signature([1; 64]);

        let result = verify_report(
            &report,
            &sha256_hash(b"wrong-config"),
            &sha256_hash(b"test-receipts"),
            1000,
            3600,
        );
        assert_eq!(result, VerifyResult::ConfigMismatch);
    }

    #[test]
    fn verify_stale_report() {
        let mut report = test_report();
        report.set_signature([1; 64]);

        let result = verify_report(
            &report,
            &sha256_hash(b"test-config"),
            &sha256_hash(b"test-receipts"),
            5000, // 4000 seconds later
            3600, // max age 3600
        );
        assert!(matches!(result, VerifyResult::Stale { .. }));
    }

    #[test]
    fn verify_unsigned_rejected() {
        let report = test_report(); // unsigned

        let result = verify_report(
            &report,
            &sha256_hash(b"test-config"),
            &sha256_hash(b"test-receipts"),
            1000,
            3600,
        );
        assert_eq!(result, VerifyResult::InvalidSignature);
    }

    #[test]
    fn content_bytes_deterministic() {
        let r1 = test_report();
        let r2 = test_report();
        assert_eq!(r1.content_bytes(), r2.content_bytes());
    }

    #[test]
    fn sha256_hash_deterministic() {
        let h1 = sha256_hash(b"hello");
        let h2 = sha256_hash(b"hello");
        assert_eq!(h1, h2);
        assert_ne!(sha256_hash(b"hello"), sha256_hash(b"world"));
    }
}
