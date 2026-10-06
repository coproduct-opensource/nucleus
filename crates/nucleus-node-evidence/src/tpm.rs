//! TPM 2.0 structures a quote is made of, parsed by hand (TCG TPM 2.0 Library
//! Part 2, "Structures"), and the quote signature check.
//!
//! Three inputs come from the node and none is trusted on its own:
//!
//! * `TPM2B_PUBLIC` — the attestation key (AK). Parsed for its key material and
//!   its object attributes. Whether this key lives in a TPM at all is the
//!   *anchor's* question ([`crate::anchor`]), not this module's.
//! * `TPMS_ATTEST` — the bytes the TPM signed. Must carry
//!   `TPM_GENERATED_VALUE` and `TPM_ST_ATTEST_QUOTE`.
//! * `TPMT_SIGNATURE` — over `H(TPMS_ATTEST)`.
//!
//! The `TPM_GENERATED_VALUE` magic is meaningful only because the AK is a
//! *restricted* signing key: a restricted key refuses to sign an external
//! digest of a buffer that starts with the magic, so a valid signature over a
//! magic-prefixed buffer was produced by the TPM's own quote command. That is
//! why [`AkPublic::require_attestation_key`] insists on `restricted | sign`.

use std::collections::BTreeSet;

use crate::Malformed;
use crate::crypto::{EcdsaSig, HashAlg, PublicKey, sha256};
use crate::wire::Reader;

const TPM_GENERATED_VALUE: u32 = 0xff54_4347;
const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;

const TPM_ALG_RSA: u16 = 0x0001;
const TPM_ALG_NULL: u16 = 0x0010;
const TPM_ALG_RSASSA: u16 = 0x0014;
const TPM_ALG_RSAPSS: u16 = 0x0016;
const TPM_ALG_ECDSA: u16 = 0x0018;
const TPM_ALG_ECC: u16 = 0x0023;

const TPM_ECC_NIST_P256: u16 = 0x0003;
const TPM_ECC_NIST_P384: u16 = 0x0004;

// TPMA_OBJECT bits.
const FIXED_TPM: u32 = 1 << 1;
const FIXED_PARENT: u32 = 1 << 4;
const SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
const RESTRICTED: u32 = 1 << 16;
const DECRYPT: u32 = 1 << 17;
const SIGN: u32 = 1 << 18;

fn field(structure: &'static str, reason: impl Into<String>) -> Malformed {
    Malformed::Field {
        structure,
        reason: reason.into(),
    }
}

/// The node's attestation key, from a `TPM2B_PUBLIC`.
#[derive(Clone, Debug)]
pub struct AkPublic {
    key: PublicKey,
    attributes: u32,
    spki_der: Vec<u8>,
}

impl AkPublic {
    /// Parse a `TPM2B_PUBLIC` (as `tpm2_createak -u` and `TPM2_ReadPublic`
    /// produce it). RSA and ECC (P-256, P-384) keys only.
    pub fn from_tpm2b_public(bytes: &[u8]) -> Result<Self, Malformed> {
        const S: &str = "TPM2B_PUBLIC";
        let mut outer = Reader::new(bytes, S);
        let inner = outer.tpm2b()?;
        outer.finish()?;
        let mut r = Reader::new(inner, "TPMT_PUBLIC");
        let kind = r.be_u16()?;
        let _name_alg = r.be_u16()?;
        let attributes = r.be_u32()?;
        let _auth_policy = r.tpm2b()?;
        // TPMT_SYM_DEF_OBJECT: NULL for a signing key; otherwise keyBits + mode.
        let sym = r.be_u16()?;
        if sym != TPM_ALG_NULL {
            r.be_u16()?;
            r.be_u16()?;
        }
        // TPMT_*_SCHEME: an algorithm, and a hash unless the scheme is NULL.
        let scheme = r.be_u16()?;
        if scheme != TPM_ALG_NULL {
            r.be_u16()?;
        }
        let key = match kind {
            TPM_ALG_RSA => {
                let _key_bits = r.be_u16()?;
                let exponent = r.be_u32()?;
                let n = r.tpm2b()?;
                PublicKey::rsa_from_parts(n, exponent)
                    .ok_or_else(|| field(S, "RSA modulus/exponent do not form a key"))?
            }
            TPM_ALG_ECC => {
                let curve = r.be_u16()?;
                let kdf = r.be_u16()?;
                if kdf != TPM_ALG_NULL {
                    r.be_u16()?;
                }
                let x = r.tpm2b()?;
                let y = r.tpm2b()?;
                match curve {
                    TPM_ECC_NIST_P256 => PublicKey::p256_from_xy(x, y),
                    TPM_ECC_NIST_P384 => PublicKey::p384_from_xy(x, y),
                    other => return Err(field(S, format!("unsupported ECC curve 0x{other:04x}"))),
                }
                .ok_or_else(|| field(S, "ECC point is not on the curve"))?
            }
            other => return Err(field(S, format!("unsupported key type 0x{other:04x}"))),
        };
        r.finish()?;
        let spki_der = key.spki_der().map_err(|e| field(S, e))?;
        Ok(Self {
            key,
            attributes,
            spki_der,
        })
    }

    /// SHA-256 of the key's SubjectPublicKeyInfo DER — the fingerprint an
    /// operator pin or an AK certificate is compared against.
    pub fn spki_sha256(&self) -> [u8; 32] {
        sha256(&self.spki_der)
    }

    pub(crate) fn spki_der(&self) -> &[u8] {
        &self.spki_der
    }

    /// The key family, for reporting.
    pub fn family(&self) -> &'static str {
        self.key.family()
    }

    /// The attributes a TPM attestation key must have, and the names of the
    /// ones this key lacks (empty when it qualifies).
    pub(crate) fn missing_attestation_attributes(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        for (bit, name) in [
            (RESTRICTED, "restricted"),
            (SIGN, "sign"),
            (FIXED_TPM, "fixedTPM"),
            (FIXED_PARENT, "fixedParent"),
            (SENSITIVE_DATA_ORIGIN, "sensitiveDataOrigin"),
        ] {
            if self.attributes & bit == 0 {
                missing.push(name);
            }
        }
        if self.attributes & DECRYPT != 0 {
            missing.push("!decrypt");
        }
        missing
    }
}

/// The fields of a `TPMS_ATTEST` of type quote that appraisal reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuoteInfo {
    /// `extraData`: the qualifying data the caller asked the TPM to sign.
    pub extra_data: Vec<u8>,
    /// `clockInfo.clock`, milliseconds the TPM has been powered.
    pub clock: u64,
    /// `clockInfo.resetCount`: TPM resets (reboots) since manufacture.
    pub reset_count: u32,
    /// `clockInfo.restartCount`: restarts/resumes since the last reset.
    pub restart_count: u32,
    /// `clockInfo.safe`.
    pub safe: bool,
    /// `firmwareVersion`.
    pub firmware_version: u64,
    /// `TPML_PCR_SELECTION`, as (bank algorithm id, selected PCR indices).
    pub pcr_selection: Vec<(u16, BTreeSet<u8>)>,
    /// `pcrDigest`: the hash of the concatenated selected PCR values.
    pub pcr_digest: Vec<u8>,
}

/// Parse the `TPMS_ATTEST` a quote signs. Anything other than a
/// TPM-generated quote structure is malformed.
pub fn parse_quote(attest: &[u8]) -> Result<QuoteInfo, Malformed> {
    const S: &str = "TPMS_ATTEST";
    let mut r = Reader::new(attest, S);
    let magic = r.be_u32()?;
    if magic != TPM_GENERATED_VALUE {
        return Err(field(
            S,
            format!("magic 0x{magic:08x} is not TPM_GENERATED_VALUE"),
        ));
    }
    let ty = r.be_u16()?;
    if ty != TPM_ST_ATTEST_QUOTE {
        return Err(field(
            S,
            format!("type 0x{ty:04x} is not TPM_ST_ATTEST_QUOTE"),
        ));
    }
    let _qualified_signer = r.tpm2b()?;
    let extra_data = r.tpm2b()?.to_vec();
    let clock = r.be_u64()?;
    let reset_count = r.be_u32()?;
    let restart_count = r.be_u32()?;
    let safe = r.u8()? != 0;
    let firmware_version = r.be_u64()?;
    let count = r.be_u32()?;
    let mut pcr_selection = Vec::new();
    for _ in 0..count {
        let alg = r.be_u16()?;
        let size = r.u8()?;
        let bits = r.bytes(usize::from(size))?;
        let mut set = BTreeSet::new();
        for (byte_index, byte) in bits.iter().enumerate() {
            for bit in 0..8u8 {
                if byte & (1 << bit) != 0 {
                    let index = byte_index
                        .checked_mul(8)
                        .and_then(|b| u8::try_from(b).ok())
                        .and_then(|b| b.checked_add(bit))
                        .ok_or_else(|| field(S, "PCR index above 255"))?;
                    set.insert(index);
                }
            }
        }
        pcr_selection.push((alg, set));
    }
    let pcr_digest = r.tpm2b()?.to_vec();
    r.finish()?;
    Ok(QuoteInfo {
        extra_data,
        clock,
        reset_count,
        restart_count,
        safe,
        firmware_version,
        pcr_selection,
        pcr_digest,
    })
}

/// Why a quote signature did not verify.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    /// The `TPMT_SIGNATURE` uses a scheme or hash this verifier does not accept.
    #[error("unsupported signature: {0}")]
    Unsupported(String),
    /// The structure did not parse.
    #[error("{0}")]
    Malformed(#[from] Malformed),
    /// The signature is well-formed and wrong.
    #[error("the quote signature does not verify under the attestation key")]
    Invalid,
}

/// Verify `signature` (a `TPMT_SIGNATURE`) over `attest` with `ak`. Returns
/// the hash algorithm the signature used, which also hashes `pcrDigest`.
pub(crate) fn verify_quote_signature(
    ak: &AkPublic,
    attest: &[u8],
    signature: &[u8],
) -> Result<HashAlg, SignatureError> {
    let mut r = Reader::new(signature, "TPMT_SIGNATURE");
    let alg = r.be_u16()?;
    let hash_id = r.be_u16()?;
    let hash = HashAlg::from_tpm(hash_id)
        .ok_or_else(|| SignatureError::Unsupported(format!("hash 0x{hash_id:04x}")))?;
    let digest = hash.digest(attest);
    let ok = match alg {
        TPM_ALG_RSASSA => {
            let sig = r.tpm2b()?;
            r.finish()?;
            ak.key.verify_rsa_pkcs1(hash, &digest, sig)
        }
        TPM_ALG_ECDSA => {
            let sig_r = r.tpm2b()?;
            let sig_s = r.tpm2b()?;
            r.finish()?;
            ak.key
                .verify_ecdsa(hash, &digest, EcdsaSig::Scalars { r: sig_r, s: sig_s })
        }
        TPM_ALG_RSAPSS => return Err(SignatureError::Unsupported("RSAPSS".into())),
        other => return Err(SignatureError::Unsupported(format!("scheme 0x{other:04x}"))),
    };
    if ok {
        Ok(hash)
    } else {
        Err(SignatureError::Invalid)
    }
}

/// Bit-for-bit builders for the structures above. Used by this crate's tests
/// as a software TPM; never by appraisal.
#[cfg(test)]
pub(crate) mod build {
    use super::*;

    pub(crate) fn tpm2b(out: &mut Vec<u8>, b: &[u8]) {
        out.extend_from_slice(&u16::try_from(b.len()).unwrap().to_be_bytes());
        out.extend_from_slice(b);
    }

    pub(crate) const AK_ATTRIBUTES: u32 =
        FIXED_TPM | FIXED_PARENT | SENSITIVE_DATA_ORIGIN | RESTRICTED | SIGN | (1 << 6);

    /// `TPM2B_PUBLIC` for a P-256 ECDSA/SHA-256 key with `attributes`.
    pub(crate) fn p256_public(vk: &p256::ecdsa::VerifyingKey, attributes: u32) -> Vec<u8> {
        let point = vk.to_encoded_point(false);
        let mut t = Vec::new();
        t.extend_from_slice(&TPM_ALG_ECC.to_be_bytes());
        t.extend_from_slice(&HashAlg::TPM_SHA256.to_be_bytes());
        t.extend_from_slice(&attributes.to_be_bytes());
        tpm2b(&mut t, &[]);
        t.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        t.extend_from_slice(&TPM_ALG_ECDSA.to_be_bytes());
        t.extend_from_slice(&HashAlg::TPM_SHA256.to_be_bytes());
        t.extend_from_slice(&TPM_ECC_NIST_P256.to_be_bytes());
        t.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        tpm2b(&mut t, point.x().unwrap());
        tpm2b(&mut t, point.y().unwrap());
        let mut out = Vec::new();
        tpm2b(&mut out, &t);
        out
    }

    /// A `TPMS_ATTEST` quote over sha256-bank `pcrs` with `extra`.
    pub(crate) fn quote(extra: &[u8], pcrs: &BTreeSet<u8>, pcr_digest: &[u8]) -> Vec<u8> {
        let mut a = Vec::new();
        a.extend_from_slice(&TPM_GENERATED_VALUE.to_be_bytes());
        a.extend_from_slice(&TPM_ST_ATTEST_QUOTE.to_be_bytes());
        tpm2b(&mut a, b"\x00\x0bsigner");
        tpm2b(&mut a, extra);
        a.extend_from_slice(&1234u64.to_be_bytes());
        a.extend_from_slice(&3u32.to_be_bytes());
        a.extend_from_slice(&0u32.to_be_bytes());
        a.push(1);
        a.extend_from_slice(&42u64.to_be_bytes());
        a.extend_from_slice(&1u32.to_be_bytes());
        a.extend_from_slice(&HashAlg::TPM_SHA256.to_be_bytes());
        a.push(3);
        let mut bits = [0u8; 3];
        for &p in pcrs {
            bits[usize::from(p / 8)] |= 1 << (p % 8);
        }
        a.extend_from_slice(&bits);
        tpm2b(&mut a, pcr_digest);
        a
    }

    /// A `TPMT_SIGNATURE` (ECDSA/SHA-256) over `attest`.
    pub(crate) fn sign(sk: &p256::ecdsa::SigningKey, attest: &[u8]) -> Vec<u8> {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let sig: p256::ecdsa::Signature = sk.sign_prehash(&sha256(attest)).unwrap();
        let (r, s) = sig.split_bytes();
        let mut out = Vec::new();
        out.extend_from_slice(&TPM_ALG_ECDSA.to_be_bytes());
        out.extend_from_slice(&HashAlg::TPM_SHA256.to_be_bytes());
        tpm2b(&mut out, &r);
        tpm2b(&mut out, &s);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap()
    }

    #[test]
    fn quote_round_trip_and_signature() {
        let sk = key();
        let ak = AkPublic::from_tpm2b_public(&build::p256_public(
            sk.verifying_key(),
            build::AK_ATTRIBUTES,
        ))
        .unwrap();
        assert!(ak.missing_attestation_attributes().is_empty());
        let pcrs: BTreeSet<u8> = [0, 7, 10].into_iter().collect();
        let attest = build::quote(b"qd", &pcrs, &[1u8; 32]);
        let q = parse_quote(&attest).unwrap();
        assert_eq!(q.extra_data, b"qd");
        assert_eq!(q.pcr_selection, vec![(HashAlg::TPM_SHA256, pcrs)]);
        assert_eq!(q.reset_count, 3);
        let sig = build::sign(&sk, &attest);
        assert_eq!(
            verify_quote_signature(&ak, &attest, &sig),
            Ok(HashAlg::Sha256)
        );
        let mut flipped = attest.clone();
        *flipped.last_mut().unwrap() ^= 1;
        assert_eq!(
            verify_quote_signature(&ak, &flipped, &sig),
            Err(SignatureError::Invalid)
        );
    }

    #[test]
    fn an_unrestricted_key_is_not_an_attestation_key() {
        let sk = key();
        let attrs = build::AK_ATTRIBUTES & !RESTRICTED;
        let ak =
            AkPublic::from_tpm2b_public(&build::p256_public(sk.verifying_key(), attrs)).unwrap();
        assert_eq!(ak.missing_attestation_attributes(), vec!["restricted"]);
    }

    #[test]
    fn non_quote_structures_are_refused() {
        let pcrs: BTreeSet<u8> = [0].into_iter().collect();
        let mut attest = build::quote(b"", &pcrs, &[0u8; 32]);
        attest[0] = 0;
        assert!(parse_quote(&attest).is_err(), "no TPM_GENERATED_VALUE");
        let mut attest = build::quote(b"", &pcrs, &[0u8; 32]);
        attest[5] = 0x17; // TPM_ST_ATTEST_CERTIFY
        assert!(parse_quote(&attest).is_err());
        let mut attest = build::quote(b"", &pcrs, &[0u8; 32]);
        attest.push(0);
        assert!(parse_quote(&attest).is_err(), "trailing bytes");
    }
}
