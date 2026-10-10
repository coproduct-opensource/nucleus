//! What vouches that the attestation key (AK) lives in a TPM.
//!
//! A quote proves only that *some* key signed some PCR values. Whether that
//! key is a TPM's restricted attestation key — rather than a software key
//! someone generated to sign a plausible structure — is the anchor's
//! question, and its answer is the weakest link of the whole appraisal. So it
//! is a closed enum, labelled in every result, and resolved **only** against
//! the relying party's own trust inputs ([`AnchorPolicy`]). The evidence names
//! which anchor it claims; it never supplies what that claim is checked
//! against.
//!
//! In descending strength:
//!
//! * [`AkAnchor::CertificateChain`] — the AK carries a certificate chaining to
//!   a root the relying party trusts (a hardware or cloud CA). Verifiable
//!   offline by anyone holding the root.
//! * [`AkAnchor::OperatorFetched`] — the relying party holds a pin for this
//!   AK that an operator obtained from an authenticated source, such as a
//!   cloud provider's API that reports a VM's vTPM keys. Not a signed artifact
//!   a stranger can check: it is the operator vouching. The weakest anchor
//!   that names hardware, and labelled so.
//! * [`AkAnchor::SoftwareTpm`] — the relying party holds a pin for this AK
//!   under a list that says the TPM is SOFTWARE (swtpm, as CI runs): no
//!   hardware holds the key, and whoever runs the emulator can sign any quote
//!   with it. It is reached only through [`AnchorPolicy::software_tpm_pins`],
//!   which a relying party fills only by asking for it by name, so a pin can
//!   never turn a software TPM into a hardware label, and an operator pin can
//!   never match a software claim (ADR 0007 C-1: the relying party's list
//!   decides the label, never the evidence's claim).
//! * [`AkAnchor::None`] — nothing ties the AK to a TPM. A quote under it is
//!   not attestation, and appraisal reports `Unattested`.
//!
//! A *claimed* chain that is internally broken (a link does not verify, or
//! the leaf certifies a different key) is not a weaker anchor; it is a false
//! one, and appraisal refuses the evidence.

use serde::{Deserialize, Serialize};
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::time::ASN1Time;

use crate::crypto::{EcdsaSig, HashAlg, PublicKey, sha256};
use crate::tpm::AkPublic;

/// The anchor the evidence claims.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AkAnchorClaim {
    /// An AK certificate chain, leaf first, each certificate base64 DER.
    CertificateChain {
        /// The chain, leaf first.
        chain: Vec<String>,
    },
    /// The operator fetched this AK from `source` (e.g. a cloud API).
    OperatorFetched {
        /// Where the AK was fetched from, as the operator names it.
        source: String,
    },
    /// The AK is a software TPM's, pinned by the operator who runs it.
    SoftwareTpm {
        /// The software TPM, as the operator names it.
        source: String,
    },
    /// No anchor is claimed.
    None,
}

/// An operator's pin: "the AK reported by `source` has this fingerprint".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorPin {
    /// The source, matched exactly against the evidence's claim.
    pub source: String,
    /// SHA-256 of the AK's SubjectPublicKeyInfo DER, hex.
    pub ak_spki_sha256: String,
}

/// The relying party's trust inputs for anchors.
/// No `Default` (ADR 0007 B-1): an empty policy must be written out, not reached by accident.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorPolicy {
    /// Root certificates (DER) an AK certificate chain may end at.
    pub trust_roots: Vec<Vec<u8>>,
    /// Operator pins the relying party has chosen to accept.
    pub operator_pins: Vec<OperatorPin>,
    /// Pins of SOFTWARE TPMs the relying party has chosen to accept, each
    /// labelled [`AkAnchor::SoftwareTpm`] wherever it anchors. Kept apart from
    /// [`Self::operator_pins`] so the label is the relying party's choice: an
    /// AK pinned here never resolves as operator-fetched, whatever the
    /// evidence claims.
    pub software_tpm_pins: Vec<OperatorPin>,
}

/// Why no anchor was established.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnanchoredReason {
    /// The evidence claims no anchor.
    NotClaimed,
    /// The chain is internally valid but ends at no root the relying party trusts.
    RootNotTrusted,
    /// The relying party holds no pin for this source and key.
    NoMatchingOperatorPin,
    /// The evidence claims a software TPM, and the relying party holds no
    /// software-TPM pin for this source and key.
    NoMatchingSoftwareTpmPin,
}

/// The anchor established for this appraisal. Labelled in every result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AkAnchor {
    /// Chains to a trusted root; the root's SPKI SHA-256 is named.
    CertificateChain {
        /// SHA-256 of the trusted root's SubjectPublicKeyInfo, hex.
        root_spki_sha256: String,
    },
    /// Vouched for by the operator through `source`.
    OperatorFetched {
        /// The source the relying party's pin names.
        source: String,
    },
    /// A software TPM the relying party chose to accept by its pin. No
    /// hardware root: an appraisal under this anchor shows the measurements
    /// match, not that a TPM chip took them.
    SoftwareTpm {
        /// The source the relying party's software-TPM pin names.
        source: String,
    },
    /// Not anchored.
    None {
        /// Why.
        reason: UnanchoredReason,
    },
}

impl AkAnchor {
    /// Whether a TPM is behind the AK by some anchor (any but `None`). A
    /// software TPM counts: the relying party chose to accept it by name.
    pub fn is_anchored(&self) -> bool {
        match self {
            Self::CertificateChain { .. }
            | Self::OperatorFetched { .. }
            | Self::SoftwareTpm { .. } => true,
            Self::None { .. } => false,
        }
    }

    /// Whether the anchor names a hardware root: a certificate chain or an
    /// operator-fetched pin. `false` for a software TPM and for no anchor.
    pub fn is_hardware(&self) -> bool {
        match self {
            Self::CertificateChain { .. } | Self::OperatorFetched { .. } => true,
            Self::SoftwareTpm { .. } | Self::None { .. } => false,
        }
    }
}

const ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
const RSA_SHA256: &str = "1.2.840.113549.1.1.11";
const RSA_SHA384: &str = "1.2.840.113549.1.1.12";

/// Does `issuer` sign `cert`? Name chaining, CA flag, and the signature.
fn issued_by(cert: &X509Certificate<'_>, issuer: &X509Certificate<'_>) -> Result<(), String> {
    if cert.issuer().as_raw() != issuer.subject().as_raw() {
        return Err(format!(
            "issuer {} does not name subject {}",
            cert.issuer(),
            issuer.subject()
        ));
    }
    if !issuer.is_ca() {
        return Err(format!("{} is not a CA certificate", issuer.subject()));
    }
    let key = PublicKey::from_spki_der(issuer.public_key().raw)?;
    let oid = cert.signature_algorithm.algorithm.to_id_string();
    let tbs = cert.tbs_certificate.as_ref();
    let sig: &[u8] = &cert.signature_value.data;
    let ok = match oid.as_str() {
        ECDSA_SHA256 => key.verify_ecdsa(
            HashAlg::Sha256,
            &HashAlg::Sha256.digest(tbs),
            EcdsaSig::Der(sig),
        ),
        ECDSA_SHA384 => key.verify_ecdsa(
            HashAlg::Sha384,
            &HashAlg::Sha384.digest(tbs),
            EcdsaSig::Der(sig),
        ),
        RSA_SHA256 => key.verify_rsa_pkcs1(HashAlg::Sha256, &HashAlg::Sha256.digest(tbs), sig),
        RSA_SHA384 => key.verify_rsa_pkcs1(HashAlg::Sha384, &HashAlg::Sha384.digest(tbs), sig),
        other => {
            return Err(format!(
                "unsupported certificate signature algorithm {other}"
            ));
        }
    };
    if ok {
        Ok(())
    } else {
        Err(format!("signature on {} does not verify", cert.subject()))
    }
}

fn valid_at(cert: &X509Certificate<'_>, at: &ASN1Time) -> Result<(), String> {
    if cert.validity().is_valid_at(*at) {
        Ok(())
    } else {
        Err(format!("{} is outside its validity period", cert.subject()))
    }
}

/// Resolve the claimed anchor against the relying party's policy at time
/// `at_unix`. `Err` means the claim is false (a broken chain), which the
/// caller refuses; an anchor the relying party simply cannot confirm is
/// `Ok(AkAnchor::None { .. })`.
pub(crate) fn resolve(
    claim: &AkAnchorClaim,
    ak: &AkPublic,
    policy: &AnchorPolicy,
    at_unix: i64,
) -> Result<AkAnchor, String> {
    match claim {
        AkAnchorClaim::None => Ok(AkAnchor::None {
            reason: UnanchoredReason::NotClaimed,
        }),
        AkAnchorClaim::OperatorFetched { source } => {
            Ok(if pinned(&policy.operator_pins, source, ak) {
                AkAnchor::OperatorFetched {
                    source: source.clone(),
                }
            } else {
                AkAnchor::None {
                    reason: UnanchoredReason::NoMatchingOperatorPin,
                }
            })
        }
        AkAnchorClaim::SoftwareTpm { source } => {
            Ok(if pinned(&policy.software_tpm_pins, source, ak) {
                AkAnchor::SoftwareTpm {
                    source: source.clone(),
                }
            } else {
                AkAnchor::None {
                    reason: UnanchoredReason::NoMatchingSoftwareTpmPin,
                }
            })
        }
        AkAnchorClaim::CertificateChain { chain } => resolve_chain(chain, ak, policy, at_unix),
    }
}

/// Whether `pins` names this source and this AK. Each list is consulted only
/// for the claim kind it labels, so a pin never crosses kinds.
fn pinned(pins: &[OperatorPin], source: &str, ak: &AkPublic) -> bool {
    let fp = hex::encode(ak.spki_sha256());
    pins.iter()
        .any(|p| p.source == source && p.ak_spki_sha256.eq_ignore_ascii_case(&fp))
}

fn resolve_chain(
    chain: &[String],
    ak: &AkPublic,
    policy: &AnchorPolicy,
    at_unix: i64,
) -> Result<AkAnchor, String> {
    use base64::Engine as _;
    let at = ASN1Time::from_timestamp(at_unix).map_err(|e| format!("appraisal time: {e}"))?;
    let ders = chain
        .iter()
        .map(|c| base64::engine::general_purpose::STANDARD.decode(c))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("chain certificate is not base64: {e}"))?;
    let certs = ders
        .iter()
        .map(|d| X509Certificate::from_der(d).map(|(_, c)| c))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("chain certificate does not parse: {e}"))?;
    let leaf = certs.first().ok_or("certificate chain is empty")?;
    let leaf_key = PublicKey::from_spki_der(leaf.public_key().raw)?.spki_der()?;
    if leaf_key != ak.spki_der() {
        return Err("the AK certificate certifies a different key than the AK".into());
    }
    for (i, cert) in certs.iter().enumerate() {
        valid_at(cert, &at)?;
        if let Some(issuer) = certs.get(i.saturating_add(1)) {
            issued_by(cert, issuer)?;
        }
    }
    // The top of the presented chain must be a trusted root or be issued by one.
    let top = certs.last().ok_or("certificate chain is empty")?;
    let top_der = ders.last().ok_or("certificate chain is empty")?;
    for root_der in &policy.trust_roots {
        let Ok((_, root)) = X509Certificate::from_der(root_der) else {
            continue;
        };
        let rooted = root_der == top_der || issued_by(top, &root).is_ok();
        if rooted {
            valid_at(&root, &at)?;
            return Ok(AkAnchor::CertificateChain {
                root_spki_sha256: hex::encode(sha256(root.public_key().raw)),
            });
        }
    }
    Ok(AkAnchor::None {
        reason: UnanchoredReason::RootNotTrusted,
    })
}
