// SPDX-License-Identifier: MIT
//
//! Where the federation issuer key lives: in the TPM, bound to the measured
//! boot, or in a file (ADR 0012).
//!
//! A provider accepts this node's assertions because the key is in the
//! issuer's JWKS. A key in a file is therefore a credential that anyone with
//! the disk — a stolen volume, a snapshot, a copied image — can use from
//! anywhere. A key in the TPM, created with an `authPolicy` that is
//! `PolicyPCR` over the boot PCRs, cannot be read out at all and signs only
//! on this TPM, in this boot state. The disk then holds only the TPM's
//! wrapping of it.
//!
//! [`KeyCustody`] is the node's choice, made once from its configuration.
//! There is no `Default` (ADR 0007 B-1): a node with a TPM configured holds
//! its key there unless the operator passes the named waiver, and a file key
//! says why it is one ([`FileCustody`]) wherever it is published.

use std::collections::BTreeSet;
use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use nucleus_node_evidence::key_attestation::boot_policy_pcrs;
pub use nucleus_node_evidence::tpm_key::TpmEndpoint;
use nucleus_node_evidence::tpm_key::{WrappedKey, create_federation_key, sign_with_federation_key};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::assertion::{AssertionSigner, Es256Signature, PublicJwk, SignError};

/// Where a node's federation key is created and held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyCustody {
    /// In the TPM, under a `PolicyPCR` over the boot PCRs.
    Tpm(TpmCustody),
    /// In a `0400` PKCS#8 file, for the stated reason.
    File(FileCustody),
}

impl KeyCustody {
    /// Which of the two on-disk layouts this custody writes.
    pub fn kind(&self) -> CustodyKind {
        match self {
            Self::Tpm(_) => CustodyKind::Tpm,
            Self::File(_) => CustodyKind::File,
        }
    }
}

/// The two on-disk layouts, as found in a key directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyKind {
    /// TPM-wrapped keys (`jwt_svid_p256_tpm_key*.json`).
    Tpm,
    /// PKCS#8 files (`jwt_svid_p256_signing_key*.der`).
    File,
}

impl fmt::Display for CustodyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Tpm => "TPM-resident",
            Self::File => "file",
        })
    }
}

/// Why a federation key is a file. Recorded in the key attestation the node
/// publishes, so a relying party reads the reason beside "not TPM-resident".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileCustody {
    /// The node has no TPM configured.
    NoTpmConfigured,
    /// The node has a TPM, and the operator waived TPM custody with
    /// [`FILE_CUSTODY_WAIVER_FLAG`].
    Waived,
}

/// The node flag that keeps the federation key in a file on a node with a
/// TPM. A flag only, never an environment variable: ambient configuration is
/// not a waiver (the Landlock waiver's rule).
pub const FILE_CUSTODY_WAIVER_FLAG: &str = "--allow-federation-key-in-file";

impl FileCustody {
    /// The reason, as published.
    pub fn reason(self) -> String {
        match self {
            Self::NoTpmConfigured => "no TPM is configured on this node".into(),
            Self::Waived => format!(
                "the node has a TPM, and its operator waived TPM custody \
                 ({FILE_CUSTODY_WAIVER_FLAG})"
            ),
        }
    }
}

/// A TPM, and the boot PCRs keys are bound to there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmCustody {
    endpoint: TpmEndpoint,
}

impl TpmCustody {
    /// Keys created in the TPM at `endpoint`, bound to
    /// [`nucleus_node_evidence::BOOT_POLICY_PCRS`].
    pub fn new(endpoint: TpmEndpoint) -> Self {
        Self { endpoint }
    }

    /// The TPM.
    pub fn endpoint(&self) -> &TpmEndpoint {
        &self.endpoint
    }

    /// Create a key bound to the boot PCRs' current values.
    pub(crate) fn create(&self) -> Result<WrappedKey, String> {
        let mut tpm = self.endpoint.connect().map_err(|e| e.to_string())?;
        create_federation_key(&mut tpm, &boot_policy_pcrs()).map_err(|e| e.to_string())
    }

    /// Whether `key` can sign in this boot: its policy against the PCRs as
    /// they are now. A key created in another boot state (an upgraded
    /// kernel, a changed command line) answers `false`.
    ///
    /// # Errors
    /// The TPM cannot be reached or read.
    pub fn usable_now(&self, key: &WrappedKey) -> Result<bool, String> {
        let mut tpm = self.endpoint.connect().map_err(|e| e.to_string())?;
        let values = tpm.pcr_read(key.policy_pcrs()).map_err(|e| e.to_string())?;
        key.policy_matches(&values).map_err(|e| e.to_string())
    }

    /// A signer for `key` in this TPM.
    pub(crate) fn signer(&self, key: WrappedKey) -> TpmP256Signer {
        TpmP256Signer {
            jwk: jwk_of(&key),
            endpoint: self.endpoint.clone(),
            key,
        }
    }
}

/// The JWK of a TPM key's public point.
pub(crate) fn jwk_of(key: &WrappedKey) -> PublicJwk {
    let (x, y) = key.point();
    PublicJwk::p256(URL_SAFE_NO_PAD.encode(x), URL_SAFE_NO_PAD.encode(y))
}

/// A federation key the TPM holds. Each signature loads the wrapped key,
/// runs `PolicyPCR` and signs, so a boot state that moved under a running
/// node stops its signatures from that moment.
pub struct TpmP256Signer {
    endpoint: TpmEndpoint,
    key: WrappedKey,
    jwk: PublicJwk,
}

impl fmt::Debug for TpmP256Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TpmP256Signer")
            .field("kid", &self.jwk.kid)
            .field("tpm", &self.endpoint)
            .finish_non_exhaustive()
    }
}

impl AssertionSigner for TpmP256Signer {
    fn kid(&self) -> &str {
        &self.jwk.kid
    }

    fn sign_es256(&self, signing_input: &[u8]) -> Result<Es256Signature, SignError> {
        let digest: [u8; 32] = Sha256::digest(signing_input).into();
        let mut tpm = self.endpoint.connect().map_err(|_| SignError::Sign)?;
        sign_with_federation_key(&mut tpm, &self.key, &digest)
            .map(Es256Signature)
            .map_err(|_| SignError::Sign)
    }

    fn public_jwk(&self) -> PublicJwk {
        self.jwk.clone()
    }
}

/// The profile of a wrapped-key file.
const WRAPPED_KEY_PROFILE: &str = "nucleus-tpm-wrapped-key/v1";

/// A wrapped-key file: the TPM's bytes, base64, and the policy's PCRs.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WrappedKeyFile {
    profile: String,
    public: String,
    private: String,
    policy_pcrs: BTreeSet<u8>,
}

/// The file bytes for `key`.
pub(crate) fn encode(key: &WrappedKey) -> Result<Vec<u8>, String> {
    serde_json::to_vec_pretty(&WrappedKeyFile {
        profile: WRAPPED_KEY_PROFILE.into(),
        public: STANDARD.encode(key.public()),
        private: STANDARD.encode(key.private()),
        policy_pcrs: key.policy_pcrs().clone(),
    })
    .map_err(|e| e.to_string())
}

/// The key in a wrapped-key file.
pub(crate) fn decode(bytes: &[u8]) -> Result<WrappedKey, String> {
    let f: WrappedKeyFile = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    if f.profile != WRAPPED_KEY_PROFILE {
        return Err(format!("unknown wrapped-key profile {:?}", f.profile));
    }
    let public = STANDARD.decode(&f.public).map_err(|e| e.to_string())?;
    let private = STANDARD.decode(&f.private).map_err(|e| e.to_string())?;
    WrappedKey::from_parts(public, private, f.policy_pcrs).map_err(|e| e.to_string())
}

/// Where a node keeps the custody statements of its published keys
/// (`nucleus_node_evidence::FederationKeyAttestation`), relative to its state
/// directory: beside the evidence documents, refreshed every epoch.
pub const KEY_ATTESTATION_STATE_FILE: &str = "node-evidence/federation-keys.json";

/// Where an issuer publishes that document, relative to the issuer URL:
/// beside the JWKS, so a relying party that fetched one finds the other.
pub const KEY_ATTESTATION_PATH: &str = ".well-known/nucleus-federation-key-attestation.json";
