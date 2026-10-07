//! Is this federation key TPM-resident, and bound to the boot the quote
//! measured? (ADR 0012.)
//!
//! A node's federation issuer key (the ES256 key in its JWKS) can be created
//! inside the TPM with an `authPolicy` that is a `PolicyPCR` over the boot
//! PCRs. The TPM then signs with it only while those PCRs hold the values they
//! held at creation, and never exports it. The node's attestation key (AK)
//! certifies the key with `TPM2_Certify`, and the node publishes that
//! certification beside its evidence. This module is the stranger's check of
//! it, in pure Rust like the rest of the verifier.
//!
//! # What a pass establishes
//!
//! [`KeyResidency::TpmBound`] for a JWKS key means all of:
//!
//! 1. The evidence itself appraised ([`crate::appraise`] ran and did not
//!    refuse), so its AK is a restricted signing key and its PCR values are
//!    the ones the TPM quoted. Read the appraisal's tier beside this result:
//!    a key bound to an `Unattested` or `Contested` boot is bound to a boot
//!    nobody vouched for.
//! 2. That AK signed a `TPMS_ATTEST` of type certify whose certified Name is
//!    the Name of the published public area. A Name is `nameAlg ||
//!    H(TPMT_PUBLIC)`, so it covers the key's point, its attributes AND its
//!    `authPolicy`: neither can be changed without changing the Name.
//! 3. The public area's point is the JWK's point.
//! 4. Its attributes are those of a TPM-generated, non-duplicable signing key
//!    that can be used ONLY through its policy: `fixedTPM | fixedParent |
//!    sensitiveDataOrigin | sign`, and NOT `userWithAuth` (which would let
//!    the empty password sign, bypassing the policy) or `adminWithPolicy`.
//! 5. Its qualified Name places it under the published storage primary in
//!    the OWNER hierarchy, not the NULL hierarchy external objects load into.
//! 6. Its `authPolicy` equals `PolicyPCR` over the stated PCR set with the
//!    QUOTED values, and that set covers [`BOOT_POLICY_PCRS`].
//!
//! # What it does not establish
//!
//! A pass says the key cannot sign outside this boot state. It does not say
//! nothing signed with it inside the boot state: a root compromise of the
//! running node can still drive the TPM while the PCRs match. See ADR 0012.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::Malformed;
use crate::appraise::{Appraisal, AppraisalPolicy, Refusal, appraise};
use crate::crypto::{HashAlg, sha256};
use crate::evidence::NodeEvidence;
use crate::tpm::{AkPublic, SignatureError, verify_quote_signature};
use crate::wire::Reader;

/// The profile of a [`FederationKeyAttestation`] document.
pub const KEY_ATTESTATION_PROFILE: &str = "nucleus-federation-key-attestation/v1";

/// The boot PCRs a federation key's policy must cover (ADR 0012 gives the
/// measurements behind each choice):
///
/// * 0 — firmware code; 2 — option ROM code.
/// * 4 — the boot manager and EFI applications (shim, the boot loader, an
///   EFI-stub kernel).
/// * 7 — Secure Boot state and its key databases.
/// * 8 — the boot loader's commands and the kernel command line.
/// * 9 — the files the boot loader read: kernel, initrd, its configuration.
/// * 14 — shim's MOK state.
///
/// Left out: 1, 3, 5 and 6 (platform configuration, the partition table and
/// wake events: measured to differ between two instances of one image, or
/// across a reboot, without the code changing) and 10 (IMA, which moves with
/// every file measured, so no key could be created against its final value).
pub const BOOT_POLICY_PCRS: [u8; 7] = [0, 2, 4, 7, 8, 9, 14];

/// [`BOOT_POLICY_PCRS`] as a set.
pub fn boot_policy_pcrs() -> BTreeSet<u8> {
    BOOT_POLICY_PCRS.into_iter().collect()
}

/// The domain tag the node certifies under: `qualifyingData` of every
/// federation-key `TPM2_Certify` is `SHA-256` of it, so a certification made
/// for another purpose is not presented as this one.
const CERTIFY_DOMAIN: &[u8] = b"nucleus-federation-key-attestation/v1/certify";

/// `qualifyingData` for a federation-key certification.
pub fn certify_qualifying_data() -> [u8; 32] {
    sha256(CERTIFY_DOMAIN)
}

const TPM_GENERATED_VALUE: u32 = 0xff54_4347;
const TPM_ST_ATTEST_CERTIFY: u16 = 0x8017;
const TPM_CC_POLICY_PCR: u32 = 0x0000_017F;
const TPM_RH_OWNER: u32 = 0x4000_0001;
const TPM_ALG_SHA256: u16 = 0x000B;
const TPM_ALG_NULL: u16 = 0x0010;
const TPM_ALG_ECC: u16 = 0x0023;
const TPM_ECC_NIST_P256: u16 = 0x0003;

// TPMA_OBJECT bits.
pub(crate) const FIXED_TPM: u32 = 1 << 1;
pub(crate) const FIXED_PARENT: u32 = 1 << 4;
pub(crate) const SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
pub(crate) const USER_WITH_AUTH: u32 = 1 << 6;
pub(crate) const ADMIN_WITH_POLICY: u32 = 1 << 7;
pub(crate) const NO_DA: u32 = 1 << 10;
pub(crate) const RESTRICTED: u32 = 1 << 16;
pub(crate) const DECRYPT: u32 = 1 << 17;
pub(crate) const SIGN: u32 = 1 << 18;

/// The attributes the node creates its federation key with: TPM-generated,
/// bound to this TPM and parent, signing only, its user role reachable only
/// through the policy. `noDA` because the key has no password to guess.
pub const FEDERATION_KEY_ATTRIBUTES: u32 =
    FIXED_TPM | FIXED_PARENT | SENSITIVE_DATA_ORIGIN | NO_DA | SIGN;

fn field(structure: &'static str, reason: impl Into<String>) -> Malformed {
    Malformed::Field {
        structure,
        reason: reason.into(),
    }
}

/// The PCR selection a `PolicyPCR` names, as the TPM marshals it: one
/// SHA-256 bank, a three-byte bitmap. The policy digest depends on these
/// exact bytes, so the attester sends them and the verifier hashes them.
///
/// # Errors
/// A PCR above 23 (outside a three-byte bitmap), or an empty set.
pub fn pcr_selection_bytes(pcrs: &BTreeSet<u8>) -> Result<Vec<u8>, Malformed> {
    const S: &str = "TPML_PCR_SELECTION";
    if pcrs.is_empty() {
        return Err(field(S, "no PCRs selected"));
    }
    let mut bits = [0u8; 3];
    for p in pcrs {
        let byte = bits
            .get_mut(usize::from(p / 8))
            .ok_or_else(|| field(S, format!("PCR {p} is outside a 3-byte selection")))?;
        *byte |= 1 << (p % 8);
    }
    let mut out = Vec::with_capacity(10);
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    out.push(3);
    out.extend_from_slice(&bits);
    Ok(out)
}

/// The `authPolicy` a fresh policy session reaches after one
/// `TPM2_PolicyPCR(pcrs)` while the PCRs hold `values` (TPM 2.0 Part 3,
/// 23.7): `H(0^32 || TPM_CC_PolicyPCR || pcrs || H(values in index order))`.
///
/// # Errors
/// A selected PCR has no value, or the selection does not marshal.
pub fn policy_pcr_digest(
    pcrs: &BTreeSet<u8>,
    values: &BTreeMap<u8, [u8; 32]>,
) -> Result<[u8; 32], Malformed> {
    let selection = pcr_selection_bytes(pcrs)?;
    let mut concat = Vec::new();
    for p in pcrs {
        let v = values
            .get(p)
            .ok_or_else(|| field("PolicyPCR", format!("no value for PCR {p}")))?;
        concat.extend_from_slice(v);
    }
    let mut buf = vec![0u8; 32];
    buf.extend_from_slice(&TPM_CC_POLICY_PCR.to_be_bytes());
    buf.extend_from_slice(&selection);
    buf.extend_from_slice(&sha256(&concat));
    Ok(sha256(&buf))
}

/// The Name of an object whose `nameAlg` is SHA-256: `0x000B ||
/// SHA-256(TPMT_PUBLIC)`.
pub fn object_name(tpmt_public: &[u8]) -> Vec<u8> {
    let mut name = TPM_ALG_SHA256.to_be_bytes().to_vec();
    name.extend_from_slice(&sha256(tpmt_public));
    name
}

/// The qualified Name of `child` under a parent whose qualified Name is
/// `parent_qualified`: `0x000B || SHA-256(parent_qualified || Name(child))`.
fn qualified_name(parent_qualified: &[u8], child_name: &[u8]) -> Vec<u8> {
    let mut buf = parent_qualified.to_vec();
    buf.extend_from_slice(child_name);
    let mut out = TPM_ALG_SHA256.to_be_bytes().to_vec();
    out.extend_from_slice(&sha256(&buf));
    out
}

/// The parts of an ECC P-256 `TPMT_PUBLIC` this check reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EccP256Public {
    /// The `TPMT_PUBLIC` bytes (inside the `TPM2B_PUBLIC`).
    pub tpmt: Vec<u8>,
    /// `nameAlg`.
    pub name_alg: u16,
    /// `objectAttributes`.
    pub attributes: u32,
    /// `authPolicy`.
    pub auth_policy: Vec<u8>,
    /// The point's x coordinate, left-padded to 32 bytes.
    pub x: [u8; 32],
    /// The point's y coordinate, left-padded to 32 bytes.
    pub y: [u8; 32],
}

fn pad32(b: &[u8]) -> Option<[u8; 32]> {
    let start = 32usize.checked_sub(b.len())?;
    let mut out = [0u8; 32];
    out.get_mut(start..)?.copy_from_slice(b);
    Some(out)
}

impl EccP256Public {
    /// Parse a `TPM2B_PUBLIC` holding an ECC NIST P-256 key.
    ///
    /// # Errors
    /// Not ECC, not P-256, or not a well-formed structure.
    pub fn from_tpm2b_public(bytes: &[u8]) -> Result<Self, Malformed> {
        const S: &str = "TPM2B_PUBLIC (ECC)";
        let mut outer = Reader::new(bytes, S);
        let tpmt = outer.tpm2b()?;
        outer.finish()?;
        let mut r = Reader::new(tpmt, "TPMT_PUBLIC");
        let kind = r.be_u16()?;
        if kind != TPM_ALG_ECC {
            return Err(field(S, format!("type 0x{kind:04x} is not ECC")));
        }
        let name_alg = r.be_u16()?;
        let attributes = r.be_u32()?;
        let auth_policy = r.tpm2b()?.to_vec();
        let sym = r.be_u16()?;
        if sym != TPM_ALG_NULL {
            r.be_u16()?; // keyBits
            r.be_u16()?; // mode
        }
        let scheme = r.be_u16()?;
        if scheme != TPM_ALG_NULL {
            r.be_u16()?; // hash
        }
        let curve = r.be_u16()?;
        if curve != TPM_ECC_NIST_P256 {
            return Err(field(S, format!("curve 0x{curve:04x} is not NIST P-256")));
        }
        let kdf = r.be_u16()?;
        if kdf != TPM_ALG_NULL {
            r.be_u16()?;
        }
        let x = pad32(r.tpm2b()?).ok_or_else(|| field(S, "x is longer than 32 bytes"))?;
        let y = pad32(r.tpm2b()?).ok_or_else(|| field(S, "y is longer than 32 bytes"))?;
        r.finish()?;
        Ok(Self {
            tpmt: tpmt.to_vec(),
            name_alg,
            attributes,
            auth_policy,
            x,
            y,
        })
    }

    /// The object's Name. Only SHA-256 names are accepted upstream.
    pub fn name(&self) -> Vec<u8> {
        object_name(&self.tpmt)
    }

    /// What disqualifies this key as a policy-bound TPM signing key; empty
    /// when it qualifies.
    pub fn federation_key_problems(&self) -> Vec<&'static str> {
        let mut problems = Vec::new();
        if self.name_alg != TPM_ALG_SHA256 {
            problems.push("nameAlg is not SHA-256");
        }
        for (bit, name) in [
            (FIXED_TPM, "fixedTPM is clear"),
            (FIXED_PARENT, "fixedParent is clear"),
            (SENSITIVE_DATA_ORIGIN, "sensitiveDataOrigin is clear"),
            (SIGN, "sign is clear"),
        ] {
            if self.attributes & bit == 0 {
                problems.push(name);
            }
        }
        for (bit, name) in [
            (
                USER_WITH_AUTH,
                "userWithAuth is set: the empty password can sign without the policy",
            ),
            (
                ADMIN_WITH_POLICY,
                "adminWithPolicy is set: an admin policy could reach the key",
            ),
            (DECRYPT, "decrypt is set"),
            (RESTRICTED, "restricted is set"),
        ] {
            if self.attributes & bit != 0 {
                problems.push(name);
            }
        }
        if self.auth_policy.len() != 32 {
            problems.push("authPolicy is not a SHA-256 digest");
        }
        problems
    }

    /// What disqualifies this key as the storage primary a federation key
    /// was created under; empty when it qualifies.
    pub fn storage_parent_problems(&self) -> Vec<&'static str> {
        let mut problems = Vec::new();
        if self.name_alg != TPM_ALG_SHA256 {
            problems.push("nameAlg is not SHA-256");
        }
        for (bit, name) in [
            (RESTRICTED, "restricted is clear"),
            (DECRYPT, "decrypt is clear"),
            (FIXED_TPM, "fixedTPM is clear"),
            (FIXED_PARENT, "fixedParent is clear"),
        ] {
            if self.attributes & bit == 0 {
                problems.push(name);
            }
        }
        if self.attributes & SIGN != 0 {
            problems.push("sign is set");
        }
        problems
    }
}

/// The fields of a `TPMS_ATTEST` of type certify this check reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifyInfo {
    /// `extraData`.
    pub extra_data: Vec<u8>,
    /// `attested.certify.name`: the Name of the certified object.
    pub name: Vec<u8>,
    /// `attested.certify.qualifiedName`.
    pub qualified_name: Vec<u8>,
}

/// Parse the `TPMS_ATTEST` a `TPM2_Certify` signs. Anything else is
/// malformed: a quote is not a certification.
///
/// # Errors
/// No `TPM_GENERATED_VALUE`, another attestation type, or a malformed
/// structure.
pub fn parse_certify(attest: &[u8]) -> Result<CertifyInfo, Malformed> {
    const S: &str = "TPMS_ATTEST (certify)";
    let mut r = Reader::new(attest, S);
    let magic = r.be_u32()?;
    if magic != TPM_GENERATED_VALUE {
        return Err(field(
            S,
            format!("magic 0x{magic:08x} is not TPM_GENERATED_VALUE"),
        ));
    }
    let ty = r.be_u16()?;
    if ty != TPM_ST_ATTEST_CERTIFY {
        return Err(field(
            S,
            format!("type 0x{ty:04x} is not TPM_ST_ATTEST_CERTIFY"),
        ));
    }
    let _qualified_signer = r.tpm2b()?;
    let extra_data = r.tpm2b()?.to_vec();
    let _clock = r.be_u64()?;
    let _reset_count = r.be_u32()?;
    let _restart_count = r.be_u32()?;
    let _safe = r.u8()?;
    let _firmware_version = r.be_u64()?;
    let name = r.tpm2b()?.to_vec();
    let qualified_name = r.tpm2b()?.to_vec();
    r.finish()?;
    Ok(CertifyInfo {
        extra_data,
        name,
        qualified_name,
    })
}

/// The document a node publishes beside its evidence and JWKS: one custody
/// statement per published federation key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationKeyAttestation {
    /// [`KEY_ATTESTATION_PROFILE`].
    pub profile: String,
    /// One entry per key the node publishes.
    pub keys: Vec<AttestedKey>,
}

/// One key's custody statement, by `kid`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestedKey {
    /// The JWK's `kid`.
    pub kid: String,
    /// Where the private key lives, as the node states it.
    pub custody: CustodyStatement,
}

/// Where a federation key's private half lives, as the node states it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyStatement {
    /// In the TPM, certified by the AK.
    Tpm(TpmCustodyStatement),
    /// In a file on the node's disk, for the stated reason. Never a pass.
    File {
        /// Why: no TPM configured, or the operator's named waiver.
        reason: String,
    },
}

/// The certification of a TPM-resident federation key. Every field is
/// base64 of the TPM's own bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TpmCustodyStatement {
    /// The key's `TPM2B_PUBLIC`.
    pub public: String,
    /// The storage primary's `TPM2B_PUBLIC` (owner hierarchy).
    pub parent_public: String,
    /// The PCRs the key's `PolicyPCR` selects.
    pub policy_pcrs: BTreeSet<u8>,
    /// The AK-signed `TPMS_ATTEST` from `TPM2_Certify`.
    pub certify_attest: String,
    /// Its `TPMT_SIGNATURE`.
    pub certify_signature: String,
}

/// The verdict on one JWKS key. Only [`KeyResidency::TpmBound`] is a pass.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "residency")]
pub enum KeyResidency {
    /// TPM-resident, certified by the evidence's AK, usable only under a
    /// `PolicyPCR` equal to the quoted values of `policy_pcrs`.
    TpmBound {
        /// The JWK's `kid`.
        kid: String,
        /// The PCRs the key is bound to.
        policy_pcrs: BTreeSet<u8>,
        /// The certified Name, hex.
        name: String,
    },
    /// The node says this key is a file. Not TPM-resident, never a pass.
    NotTpmResident {
        /// The JWK's `kid`.
        kid: String,
        /// The node's stated reason.
        reason: String,
    },
    /// The attestation document says nothing about this key. Absence is not
    /// a pass (ADR 0007 A-5).
    Unstated {
        /// The JWK's `kid`.
        kid: String,
    },
}

impl KeyResidency {
    /// Whether this is the one passing verdict.
    pub fn is_tpm_bound(&self) -> bool {
        match self {
            Self::TpmBound { .. } => true,
            Self::NotTpmResident { .. } | Self::Unstated { .. } => false,
        }
    }
}

/// Why a key's custody statement was refused: a statement that is false, as
/// opposed to one that honestly says "file".
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error, Serialize)]
#[serde(rename_all = "snake_case", tag = "refusal", content = "detail")]
pub enum KeyRefusal {
    /// The evidence itself was refused, so nothing it carries can vouch for a
    /// key.
    #[error("node evidence refused: {0}")]
    Evidence(Refusal),
    /// The attestation document's profile is not [`KEY_ATTESTATION_PROFILE`].
    #[error("unknown key attestation profile {0:?}")]
    UnknownProfile(String),
    /// The JWKS or the attestation document is malformed.
    #[error("malformed: {0}")]
    Malformed(String),
    /// The certified public area is not this JWK's key.
    #[error("{kid}: the certified public area is not the JWK's key")]
    JwkMismatch {
        /// The `kid`.
        kid: String,
    },
    /// The key's attributes do not make it a policy-bound TPM signing key.
    #[error("{kid}: not a policy-bound TPM signing key: {problems:?}")]
    KeyAttributes {
        /// The `kid`.
        kid: String,
        /// What is wrong.
        problems: Vec<&'static str>,
    },
    /// The stated parent is not a storage primary.
    #[error("{kid}: the stated parent is not a storage key: {problems:?}")]
    ParentAttributes {
        /// The `kid`.
        kid: String,
        /// What is wrong.
        problems: Vec<&'static str>,
    },
    /// The certification does not verify under the evidence's AK.
    #[error("{kid}: the certification does not verify under the evidence's AK ({reason})")]
    CertifySignature {
        /// The `kid`.
        kid: String,
        /// Why.
        reason: String,
    },
    /// The certification was not made for a federation key.
    #[error("{kid}: the certification's qualifying data is not the federation-key domain")]
    QualifyingData {
        /// The `kid`.
        kid: String,
    },
    /// The certified Name is not the Name of the published public area: the
    /// public area (its point, attributes or `authPolicy`) was changed after
    /// the TPM certified it, or belongs to another key.
    #[error("{kid}: the certified Name is not the Name of the published public area")]
    NameMismatch {
        /// The `kid`.
        kid: String,
    },
    /// The qualified Name does not place the key under the stated storage
    /// primary in the owner hierarchy.
    #[error("{kid}: the key is not under the stated storage primary in the owner hierarchy")]
    QualifiedNameMismatch {
        /// The `kid`.
        kid: String,
    },
    /// A PCR the policy selects is not in the quote, so its value is unknown.
    #[error("{kid}: the policy selects PCRs the quote does not cover: {missing:?}")]
    PolicyNotQuoted {
        /// The `kid`.
        kid: String,
        /// The PCRs.
        missing: BTreeSet<u8>,
    },
    /// The policy leaves out boot PCRs [`BOOT_POLICY_PCRS`] requires.
    #[error("{kid}: the policy leaves out boot PCRs {missing:?}")]
    PolicyTooNarrow {
        /// The `kid`.
        kid: String,
        /// The PCRs.
        missing: BTreeSet<u8>,
    },
    /// The `authPolicy` is not `PolicyPCR` over the quoted values: the key is
    /// bound to some other boot state, or to another policy altogether.
    #[error("{kid}: the key's authPolicy is not PolicyPCR over the quoted PCR values")]
    PolicyMismatch {
        /// The `kid`.
        kid: String,
    },
}

impl From<Malformed> for KeyRefusal {
    fn from(m: Malformed) -> Self {
        Self::Malformed(m.to_string())
    }
}

fn b64(field: &str, s: &str) -> Result<Vec<u8>, KeyRefusal> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| KeyRefusal::Malformed(format!("{field}: {e}")))
}

fn b64url32(field: &str, s: &str) -> Result<[u8; 32], KeyRefusal> {
    let v = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| KeyRefusal::Malformed(format!("{field}: {e}")))?;
    <[u8; 32]>::try_from(v).map_err(|_| KeyRefusal::Malformed(format!("{field}: not 32 bytes")))
}

/// One JWKS entry: `kid` and the P-256 point.
struct Jwk {
    kid: String,
    x: [u8; 32],
    y: [u8; 32],
}

fn jwks_keys(jwks: &serde_json::Value) -> Result<Vec<Jwk>, KeyRefusal> {
    let keys = jwks
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| KeyRefusal::Malformed("the JWKS has no `keys` array".into()))?;
    if keys.is_empty() {
        return Err(KeyRefusal::Malformed("the JWKS has no keys".into()));
    }
    let mut out = Vec::new();
    for k in keys {
        let s = |name: &str| {
            k.get(name)
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| KeyRefusal::Malformed(format!("a JWK has no string `{name}`")))
        };
        let kid = s("kid")?.to_string();
        if s("kty")? != "EC" || s("crv")? != "P-256" {
            return Err(KeyRefusal::Malformed(format!("{kid}: not an EC P-256 JWK")));
        }
        out.push(Jwk {
            x: b64url32("x", s("x")?)?,
            y: b64url32("y", s("y")?)?,
            kid,
        });
    }
    Ok(out)
}

/// Appraise `evidence` and, against it, the custody of every key in `jwks`.
///
/// The evidence is appraised here, not taken as an already-made appraisal,
/// so the PCR values and the AK this reads are the ones the appraisal
/// verified: there is no way to call this with PCRs the TPM did not quote
/// (ADR 0007 C-2). The [`Appraisal`] is returned for its tier, which a
/// relying party reads beside each key's [`KeyResidency`].
///
/// # Errors
/// The evidence is refused, a document is malformed, or a key's TPM custody
/// statement is false ([`KeyRefusal`]). A key the node says is in a file is
/// not an error: it is [`KeyResidency::NotTpmResident`].
pub fn appraise_federation_keys(
    evidence: &NodeEvidence,
    policy: &AppraisalPolicy<'_>,
    jwks: &serde_json::Value,
    attestation: &FederationKeyAttestation,
) -> Result<(Appraisal, Vec<KeyResidency>), KeyRefusal> {
    let appraisal = appraise(evidence, policy).map_err(KeyRefusal::Evidence)?;
    if attestation.profile != KEY_ATTESTATION_PROFILE {
        return Err(KeyRefusal::UnknownProfile(attestation.profile.clone()));
    }
    // `appraise` accepted these: a restricted signing AK, and PCR values that
    // hash to the digest it signed.
    let ak = AkPublic::from_tpm2b_public(&b64("tpm.ak_public", &evidence.tpm.ak_public)?)?;
    let mut quoted = BTreeMap::new();
    for (index, value) in &evidence.tpm.pcrs {
        let v = hex::decode(value)
            .ok()
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
            .ok_or_else(|| KeyRefusal::Malformed(format!("tpm.pcrs.{index}")))?;
        quoted.insert(*index, v);
    }
    let mut statements: BTreeMap<&str, &CustodyStatement> = BTreeMap::new();
    for k in &attestation.keys {
        if statements.insert(&k.kid, &k.custody).is_some() {
            return Err(KeyRefusal::Malformed(format!(
                "{}: two custody statements for one kid",
                k.kid
            )));
        }
    }
    let mut verdicts = Vec::new();
    for jwk in jwks_keys(jwks)? {
        let verdict = match statements.get(jwk.kid.as_str()) {
            None => KeyResidency::Unstated { kid: jwk.kid },
            Some(CustodyStatement::File { reason }) => KeyResidency::NotTpmResident {
                kid: jwk.kid,
                reason: reason.clone(),
            },
            Some(CustodyStatement::Tpm(s)) => tpm_bound(&ak, &quoted, &jwk, s)?,
        };
        verdicts.push(verdict);
    }
    Ok((appraisal, verdicts))
}

fn tpm_bound(
    ak: &AkPublic,
    quoted: &BTreeMap<u8, [u8; 32]>,
    jwk: &Jwk,
    s: &TpmCustodyStatement,
) -> Result<KeyResidency, KeyRefusal> {
    let kid = || jwk.kid.clone();
    // 1. The AK signed this certification; nothing in it is read before that.
    let attest = b64("certify_attest", &s.certify_attest)?;
    let signature = b64("certify_signature", &s.certify_signature)?;
    match verify_quote_signature(ak, &attest, &signature) {
        Ok(HashAlg::Sha256 | HashAlg::Sha384) => {}
        Err(SignatureError::Invalid) => {
            return Err(KeyRefusal::CertifySignature {
                kid: kid(),
                reason: "the signature is wrong".into(),
            });
        }
        Err(e @ (SignatureError::Unsupported(_) | SignatureError::Malformed(_))) => {
            return Err(KeyRefusal::CertifySignature {
                kid: kid(),
                reason: e.to_string(),
            });
        }
    }
    let certify = parse_certify(&attest)?;
    if certify.extra_data != certify_qualifying_data() {
        return Err(KeyRefusal::QualifyingData { kid: kid() });
    }
    // 2. It certifies THIS public area, so the point, the attributes and the
    //    authPolicy below are what the TPM holds.
    let key = EccP256Public::from_tpm2b_public(&b64("public", &s.public)?)?;
    if certify.name != key.name() {
        return Err(KeyRefusal::NameMismatch { kid: kid() });
    }
    if (key.x, key.y) != (jwk.x, jwk.y) {
        return Err(KeyRefusal::JwkMismatch { kid: kid() });
    }
    let problems = key.federation_key_problems();
    if !problems.is_empty() {
        return Err(KeyRefusal::KeyAttributes {
            kid: kid(),
            problems,
        });
    }
    // 3. Under the stated storage primary, in the owner hierarchy.
    let parent = EccP256Public::from_tpm2b_public(&b64("parent_public", &s.parent_public)?)?;
    let problems = parent.storage_parent_problems();
    if !problems.is_empty() {
        return Err(KeyRefusal::ParentAttributes {
            kid: kid(),
            problems,
        });
    }
    let parent_qn = qualified_name(&TPM_RH_OWNER.to_be_bytes(), &parent.name());
    if certify.qualified_name != qualified_name(&parent_qn, &key.name()) {
        return Err(KeyRefusal::QualifiedNameMismatch { kid: kid() });
    }
    // 4. Its policy is PolicyPCR over the boot PCRs at the QUOTED values.
    let missing: BTreeSet<u8> = s
        .policy_pcrs
        .iter()
        .filter(|p| !quoted.contains_key(p))
        .copied()
        .collect();
    if !missing.is_empty() {
        return Err(KeyRefusal::PolicyNotQuoted {
            kid: kid(),
            missing,
        });
    }
    let missing: BTreeSet<u8> = boot_policy_pcrs()
        .difference(&s.policy_pcrs)
        .copied()
        .collect();
    if !missing.is_empty() {
        return Err(KeyRefusal::PolicyTooNarrow {
            kid: kid(),
            missing,
        });
    }
    if key.auth_policy != policy_pcr_digest(&s.policy_pcrs, quoted)? {
        return Err(KeyRefusal::PolicyMismatch { kid: kid() });
    }
    Ok(KeyResidency::TpmBound {
        kid: kid(),
        policy_pcrs: s.policy_pcrs.clone(),
        name: hex::encode(certify.name),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden vectors computed outside this crate: tpm2-tools 5.6
    /// `tpm2_createpolicy --policy-pcr -l sha256:0,2,4,7,8,9,14` against a
    /// fresh swtpm (libtpms runs the trial `PolicyPCR`), before and after
    /// `tpm2_pcrextend 8:sha256=08…08`.
    #[test]
    fn the_policy_digest_matches_an_independent_tpm_stack() {
        let mut values: BTreeMap<u8, [u8; 32]> = BOOT_POLICY_PCRS
            .into_iter()
            .map(|p| (p, [0u8; 32]))
            .collect();
        assert_eq!(
            hex::encode(policy_pcr_digest(&boot_policy_pcrs(), &values).unwrap()),
            "63558ba5687aef27b8773567475fcc38436969ec181d5434db8dbd54202685bd"
        );
        let mut extended = [0u8; 64];
        extended[32..].copy_from_slice(&[0x08; 32]);
        let pcr8 = sha256(&extended);
        assert_eq!(
            hex::encode(pcr8),
            "3d71c1052c4d9c676b7ef6f5bed4650cd060d64db29dd69ffa192d38dbbada18"
        );
        values.insert(8, pcr8);
        assert_eq!(
            hex::encode(policy_pcr_digest(&boot_policy_pcrs(), &values).unwrap()),
            "f602555acf1444c39fa26246c90efcd525f32aaa84076ad1b3f68ab9bf48cecf"
        );
    }

    #[test]
    fn a_selection_outside_three_bytes_or_empty_is_refused() {
        assert!(pcr_selection_bytes(&BTreeSet::new()).is_err());
        assert!(pcr_selection_bytes(&[24].into_iter().collect()).is_err());
        assert_eq!(
            pcr_selection_bytes(&[0, 8, 23].into_iter().collect()).unwrap(),
            vec![0, 0, 0, 1, 0, 0x0B, 3, 0x01, 0x01, 0x80]
        );
    }
}
