//! The launch quote: a pod's launch as a TPM statement (ADR 0016 D2).
//!
//! At each launch the node asks its TPM for a challenge-response quote, from
//! the same AK that signs its epoch evidence, over
//!
//! ```text
//! nonce = SHA-256("nucleus-launch-v1" ‖ SVID SubjectPublicKeyInfo DER ‖ kernel ‖ rootfs ‖ config)
//! ```
//!
//! stores the evidence document by its SHA-256 beside its epoch evidence, and
//! names that digest in the SVID (OID `.1.7`). The quote binds the leaf's key,
//! not the certificate, so the certificate can name the quote. The encoding is
//! injective: the tag is fixed, a DER `SubjectPublicKeyInfo` carries its own
//! length, and the three measurements are 32 bytes each.
//!
//! A relying party holding the leaf, the quote document and its own appraisal
//! inputs then checks, in [`appraise_launch_quote`]:
//!
//! 1. the leaf names a launch quote, and the document is the one it names;
//! 2. the quote was taken over THIS leaf's key and THIS measurement: the nonce
//!    is recomputed from the leaf, never read from the document;
//! 3. the quote appraises `Attested` under the relying party's reference
//!    manifest and AK anchors (`nucleus_node_evidence::appraise`, the one
//!    verifier of node evidence).
//!
//! What it buys: a CA key taken from a running node no longer forges a launch,
//! because the forger also needs a quote over the forged key from an AK on an
//! Attested boot.

use std::sync::Arc;

use nucleus_node_evidence::{
    AnchorPolicy, Appraisal, AppraisalPolicy, FreshnessExpectation, KeyBinding, NodeEvidence,
    Nonce, ReferenceManifest, StaleReason, Tier, appraise, evidence_digest,
};

use crate::attestation::{Hash256, LaunchAttestation, format_hash, hash_bytes};
use crate::{Error, Result, oid};

/// The domain tag the launch nonce starts with.
pub const LAUNCH_NONCE_DOMAIN: &[u8] = b"nucleus-launch-v1";

/// The nonce a launch quote is taken over:
/// `SHA-256("nucleus-launch-v1" ‖ spki_der ‖ kernel ‖ rootfs ‖ config)`.
pub fn launch_nonce(spki_der: &[u8], launch: &LaunchAttestation) -> Hash256 {
    let mut pre = Vec::with_capacity(LAUNCH_NONCE_DOMAIN.len() + spki_der.len() + 96);
    pre.extend_from_slice(LAUNCH_NONCE_DOMAIN);
    pre.extend_from_slice(spki_der);
    pre.extend_from_slice(launch.kernel_hash());
    pre.extend_from_slice(launch.rootfs_hash());
    pre.extend_from_slice(launch.config_hash());
    hash_bytes(&pre)
}

/// What takes a launch quote: the node's TPM attester.
///
/// Implemented by the node. It quotes over `nonce` with challenge-response
/// freshness, stores the evidence document where relying parties fetch it by
/// digest, and returns `SHA-256` of the stored bytes.
pub trait LaunchQuoter: Send + Sync {
    /// Quote over `nonce`, store the document, and return its digest.
    ///
    /// # Errors
    ///
    /// The TPM cannot quote, or the document cannot be stored. The caller
    /// issues nothing then: a launch the node was asked to root in its TPM is
    /// never issued with only the CA's word for it.
    fn quote_launch(&self, nonce: Hash256) -> QuoteFuture<'_>;
}

/// The future [`LaunchQuoter::quote_launch`] returns.
pub type QuoteFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<Hash256>> + Send + 'a>>;

/// How a measured launch's certificates are rooted, chosen by the node.
///
/// No `Default` (ADR 0007 B-1): a node with a TPM asks for [`Self::Tpm`] by
/// name, and nothing infers it from an absent field.
#[derive(Clone)]
pub enum LaunchRooting {
    /// The node CA's signature alone vouches for the measurement.
    NodeCa,
    /// Each issue is also quoted by the node's TPM, and the leaf names the
    /// quote (OID `.1.7`).
    Tpm(Arc<dyn LaunchQuoter>),
}

impl std::fmt::Debug for LaunchRooting {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NodeCa => f.write_str("NodeCa"),
            Self::Tpm(_) => f.write_str("Tpm(..)"),
        }
    }
}

/// The `.1.7` extension value: `SEQUENCE { INTEGER 1, OCTET STRING digest }`,
/// the shape of the `.1.2` and `.1.4` extensions.
pub(crate) fn launch_quote_extension_value(quote_sha256: &Hash256) -> Vec<u8> {
    let mut der = vec![0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20];
    der.extend_from_slice(quote_sha256);
    der
}

/// The launch-quote digest a leaf names (OID `.1.7`), if it carries one.
///
/// # Errors
///
/// The leaf does not parse, or carries the extension with a value that is not
/// a version-1 digest: a statement nobody can read is refused, never read as
/// absent (ADR 0007 A-2).
pub fn extract_launch_quote_digest(cert_der: &[u8]) -> Result<Option<Hash256>> {
    use x509_parser::prelude::{FromDer, X509Certificate};
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| Error::Certificate(format!("leaf does not parse: {e}")))?;
    let Some(ext) = cert
        .extensions()
        .iter()
        .find(|e| e.oid.as_bytes() == oid::OID_NUCLEUS_LAUNCH_QUOTE_BYTES)
    else {
        return Ok(None);
    };
    match ext.value {
        [0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20, digest @ ..] => {
            let digest: Hash256 = digest.try_into().map_err(|_| unreadable())?;
            Ok(Some(digest))
        }
        _ => Err(unreadable()),
    }
}

fn unreadable() -> Error {
    Error::VerificationFailed("leaf carries an unreadable launch-quote extension".into())
}

/// The DER `SubjectPublicKeyInfo` of a certificate.
///
/// # Errors
///
/// The certificate does not parse.
pub fn leaf_spki(cert_der: &[u8]) -> Result<Vec<u8>> {
    use x509_parser::prelude::{FromDer, X509Certificate};
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| Error::Certificate(format!("leaf does not parse: {e}")))?;
    Ok(cert.tbs_certificate.subject_pki.raw.to_vec())
}

/// The DER `SubjectPublicKeyInfo` a PEM CSR requests: the key the leaf will
/// carry, read before the CA signs, so the quote can be taken over it.
pub(crate) fn csr_spki(csr_pem: &str) -> Result<Vec<u8>> {
    use x509_parser::prelude::{FromDer, X509CertificationRequest};
    let pem = pem::parse(csr_pem)
        .map_err(|e| Error::CsrGeneration(format!("CSR PEM does not parse: {e}")))?;
    let (_, csr) = X509CertificationRequest::from_der(pem.contents())
        .map_err(|e| Error::CsrGeneration(format!("CSR does not parse: {e}")))?;
    Ok(csr.certification_request_info.subject_pki.raw.to_vec())
}

/// Everything the relying party brings to a launch-quote appraisal. None of it
/// comes from the quote.
#[derive(Clone, Copy, Debug)]
pub struct LaunchQuotePolicy<'a> {
    /// The node's executor key and federation set, as the operator publishes
    /// them: the binding every quote the node takes carries.
    pub expected_binding: &'a KeyBinding,
    /// The reference manifest the node's boot must match.
    pub reference: &'a ReferenceManifest,
    /// The trust inputs that anchor the AK.
    pub anchors: &'a AnchorPolicy,
    /// The time to check certificate validity at, Unix seconds.
    pub now: i64,
}

/// A launch quote that appraised `Attested` over this leaf's key and
/// measurement. Built only by [`appraise_launch_quote`] (C-1, C-2).
#[derive(Clone, Debug)]
pub struct Appraised {
    quote_sha256: Hash256,
    appraisal: Appraisal,
}

impl Appraised {
    /// `SHA-256` of the quote document, as the leaf names it.
    pub fn quote_sha256(&self) -> &Hash256 {
        &self.quote_sha256
    }

    /// The appraisal: tier `Attested`, its AK anchor, and what was not checked.
    pub fn appraisal(&self) -> &Appraisal {
        &self.appraisal
    }
}

/// What a verified launch is rooted in. Closed: a root added later does not
/// compile at a match until someone says what it vouches for (E-2).
#[derive(Clone, Debug)]
pub enum LaunchRoot {
    /// The node CA's signature alone. A CA key taken from a running node mints
    /// launches indistinguishable from this one.
    NodeCa,
    /// A TPM quote over the leaf's key and measurement, appraised `Attested`.
    Tpm(Appraised),
}

/// Appraise the launch quote `document` for the leaf `leaf_der`, whose
/// chain-checked launch claim is `launch`.
///
/// # Errors
///
/// The leaf names no launch quote; the document is not the one it names; the
/// document is not node evidence; the quote is refused by the verifier; or it
/// appraises anything but `Attested`. Each is named.
pub(crate) fn appraise_launch_quote(
    leaf_der: &[u8],
    launch: &LaunchAttestation,
    document: &[u8],
    policy: &LaunchQuotePolicy<'_>,
) -> Result<Appraised> {
    let refused = |why: String| Error::VerificationFailed(format!("launch quote: {why}"));
    let named = extract_launch_quote_digest(leaf_der)?.ok_or_else(|| {
        refused("the leaf names no launch quote (OID 1.3.6.1.4.1.57212.1.7)".into())
    })?;
    let held = evidence_digest(document);
    if held != named {
        return Err(refused(format!(
            "the document hashes to {} but the leaf names {}",
            format_hash(&held),
            format_hash(&named)
        )));
    }
    let evidence: NodeEvidence = serde_json::from_slice(document)
        .map_err(|e| refused(format!("the document is not node evidence: {e}")))?;
    // Recomputed from the leaf, never read from the document: this is what
    // ties the TPM's signature to this key and this measurement.
    let sent = launch_nonce(&leaf_spki(leaf_der)?, launch);
    let sent = Nonce::new(sent.to_vec()).map_err(refused)?;
    // Exhaustive, so an input added to the policy cannot go unused (E-1).
    let LaunchQuotePolicy {
        expected_binding,
        reference,
        anchors,
        now,
    } = *policy;
    let appraisal = appraise(
        &evidence,
        &AppraisalPolicy {
            expected_binding,
            freshness: FreshnessExpectation::Challenge { sent },
            reference,
            anchors,
            now,
        },
    )
    .map_err(|e| refused(format!("the quote is refused: {e}")))?;
    // Only `Attested` roots a launch. No `_` arm (E-2).
    match appraisal.tier() {
        Tier::Attested => Ok(Appraised {
            quote_sha256: named,
            appraisal,
        }),
        Tier::Expired {
            reason: StaleReason::NonceMismatch,
        } => Err(refused(
            "the quote was not taken over this leaf's key and measurement".into(),
        )),
        Tier::Contested => Err(refused(
            "the quote appraises `contested`: the node's boot diverges from the reference".into(),
        )),
        Tier::Expired { reason } => Err(refused(format!(
            "the quote appraises `expired` ({reason:?}), not attested"
        ))),
        Tier::Unattested { reason } => Err(refused(format!(
            "the quote appraises `unattested` ({reason:?}): nothing anchors its AK"
        ))),
    }
}

#[cfg(test)]
#[path = "launch_quote_tests.rs"]
mod tests;
