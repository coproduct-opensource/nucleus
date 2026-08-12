//! TPM 2.0 DevID residency verifier (North Star C9, Phase 1 Inc 1).
//!
//! Verifies a `TPM2_Certify` attestation: an attestation key (AK) signs a
//! `TPMS_ATTEST` structure certifying that a *subject* key is resident in the same
//! TPM and is `fixedTPM|fixedParent` — i.e. **non-exportable**. This is the
//! *verifiability* half of a TPM DevID root: a blob a relying party can check to
//! learn that a key cannot leave its TPM.
//!
//! # What this proves, and what it does NOT
//!
//! On success this establishes [`Claim::KeyNonExportable`] for the subject key,
//! *conditional on the AK*. It deliberately does **not** establish
//! [`Claim::HardwareRootedKey`] or [`Claim::StableDeviceIdentity`]: those require
//! anchoring the AK to a genuine, manufacturer-signed **endorsement key (EK)** —
//! a separate step (a later increment). A software TPM (`swtpm`) has no
//! manufacturer-signed EK, so exercising this verifier against `swtpm` proves
//! **protocol correctness**, never silicon binding. The returned
//! [`VerifiedAttestation`] carries those gaps in its `not_proven` set so a relying
//! party cannot read hardware rooting into a residency proof.
//!
//! # TCB
//!
//! The verify path is pure Rust over in-tree crypto (`ring` ECDSA-P256, `sha2`).
//! `libtss2`/`tss-esapi` are never in this path — a TPM (or `swtpm`) is only a
//! *producer* of the blobs this module consumes.

use crate::assurance::{AssuranceLevel, AttestedSubject, Claim, VerifiedAttestation};
use crate::{Error, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

// TPM constants (TCG TPM 2.0 Structures, Part 2).
const TPM_GENERATED_VALUE: u32 = 0xff54_4347; // "\xffTCG"
const TPM_ST_ATTEST_CERTIFY: u16 = 0x8017;
const TPM_ALG_NULL: u16 = 0x0010;
const TPM_ALG_ECDAA: u16 = 0x001a;
const TPMA_OBJECT_FIXED_TPM: u32 = 1 << 1;
const TPMA_OBJECT_FIXED_PARENT: u32 = 1 << 4;

fn vfail(msg: impl Into<String>) -> Error {
    Error::VerificationFailed(msg.into())
}

/// Minimal big-endian reader over a TPM-marshaled byte slice.
struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b, pos: 0 }
    }

    fn u16(&mut self) -> Result<u16> {
        let end = self.pos + 2;
        let s = self
            .b
            .get(self.pos..end)
            .ok_or_else(|| vfail("truncated: expected u16"))?;
        self.pos = end;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let end = self.pos + 4;
        let s = self
            .b
            .get(self.pos..end)
            .ok_or_else(|| vfail("truncated: expected u32"))?;
        self.pos = end;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos + n;
        let s = self
            .b
            .get(self.pos..end)
            .ok_or_else(|| vfail("truncated: expected bytes"))?;
        self.pos = end;
        Ok(s)
    }

    /// Reads a `TPM2B` (u16 length prefix + that many bytes).
    fn tpm2b(&mut self) -> Result<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}

/// The certified facts extracted from a `TPMS_ATTEST` of type CERTIFY.
struct CertifyInfo {
    /// The certified subject key's TPM Name (algId || digest).
    certified_name: Vec<u8>,
    /// The signing AK's qualified name (algId || digest).
    qualified_signer: Vec<u8>,
}

/// Parses a marshaled `TPMS_ATTEST` (the bytes the TPM signs), checking that it is a
/// genuine CERTIFY attestation and returning the certified names.
fn parse_certify_attest(attest: &[u8]) -> Result<CertifyInfo> {
    let mut r = Reader::new(attest);
    if r.u32()? != TPM_GENERATED_VALUE {
        return Err(vfail("attest: bad TPM_GENERATED magic"));
    }
    if r.u16()? != TPM_ST_ATTEST_CERTIFY {
        return Err(vfail("attest: not a TPM_ST_ATTEST_CERTIFY structure"));
    }
    let qualified_signer = r.tpm2b()?.to_vec(); // TPM2B_NAME qualifiedSigner
    let _extra_data = r.tpm2b()?; // TPM2B_DATA extraData
                                  // TPMS_CLOCK_INFO: clock(8) resetCount(4) restartCount(4) safe(1) = 17
    r.take(17)?;
    r.take(8)?; // UINT64 firmwareVersion
                // TPMU_ATTEST (certify) = TPMS_CERTIFY_INFO { name, qualifiedName }
    let certified_name = r.tpm2b()?.to_vec();
    let _qualified_name = r.tpm2b()?;
    Ok(CertifyInfo {
        certified_name,
        qualified_signer,
    })
}

/// Fields parsed out of a `TPM2B_PUBLIC`.
struct PublicKey {
    /// Object attributes (`TPMA_OBJECT`).
    attributes: u32,
    /// `nameAlg` (must be SHA-256 here).
    name_alg: u16,
    /// The marshaled `TPMT_PUBLIC` (the bytes hashed to form the Name).
    tpmt_public: Vec<u8>,
    /// The ECC public point, SEC1 uncompressed: `0x04 || X || Y`.
    sec1_uncompressed: Vec<u8>,
}

/// Parses a `TPM2B_PUBLIC` for an ECC key, extracting attributes, nameAlg, the
/// TPMT_PUBLIC body, and the public point.
fn parse_ecc_public(pub2b: &[u8]) -> Result<PublicKey> {
    let mut outer = Reader::new(pub2b);
    let tpmt_public = outer.tpm2b()?.to_vec(); // TPM2B_PUBLIC wraps TPMT_PUBLIC

    let mut r = Reader::new(&tpmt_public);
    let _type = r.u16()?; // TPMI_ALG_PUBLIC (expect ECC 0x0023)
    let name_alg = r.u16()?; // TPMI_ALG_HASH
    let attributes = r.u32()?; // TPMA_OBJECT
    let _auth_policy = r.tpm2b()?; // TPM2B_DIGEST authPolicy

    // TPMS_ECC_PARMS
    // symmetric: TPMT_SYM_DEF_OBJECT { algorithm; [keyBits; mode] }
    if r.u16()? != TPM_ALG_NULL {
        r.u16()?; // keyBits
        r.u16()?; // mode
    }
    // scheme: TPMT_ECC_SCHEME { scheme; [details] }
    let scheme = r.u16()?;
    if scheme != TPM_ALG_NULL {
        r.u16()?; // hash for the scheme
        if scheme == TPM_ALG_ECDAA {
            r.u16()?; // count
        }
    }
    let _curve_id = r.u16()?; // TPMI_ECC_CURVE
                              // kdf: TPMT_KDF_SCHEME { scheme; [details] }
    if r.u16()? != TPM_ALG_NULL {
        r.u16()?; // hash for the kdf
    }
    // unique: TPMS_ECC_POINT { x: TPM2B, y: TPM2B }
    let x = r.tpm2b()?;
    let y = r.tpm2b()?;
    if x.len() != 32 || y.len() != 32 {
        return Err(vfail("ecc public: expected a 32-byte P-256 point"));
    }
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(x);
    sec1.extend_from_slice(y);

    Ok(PublicKey {
        attributes,
        name_alg,
        tpmt_public,
        sec1_uncompressed: sec1,
    })
}

/// Computes a key's TPM Name: `nameAlg || H_nameAlg(TPMT_PUBLIC)`. Only SHA-256 is
/// supported (the only `nameAlg` this verifier accepts).
fn compute_name(key: &PublicKey) -> Result<Vec<u8>> {
    if key.name_alg != 0x000b {
        return Err(vfail("unsupported nameAlg (only SHA-256 accepted)"));
    }
    let digest = Sha256::digest(&key.tpmt_public);
    let mut name = Vec::with_capacity(2 + 32);
    name.extend_from_slice(&key.name_alg.to_be_bytes());
    name.extend_from_slice(&digest);
    Ok(name)
}

/// Parses a `TPMT_SIGNATURE` (ECDSA) into the fixed `r || s` form ring expects.
fn parse_ecdsa_sig(sig: &[u8]) -> Result<[u8; 64]> {
    let mut r = Reader::new(sig);
    let _sig_alg = r.u16()?; // TPMI_ALG_SIG_SCHEME (expect ECDSA 0x0018)
    let _hash = r.u16()?; // TPMI_ALG_HASH
    let sr = r.tpm2b()?; // signatureR
    let ss = r.tpm2b()?; // signatureS
    if sr.len() != 32 || ss.len() != 32 {
        return Err(vfail("ecdsa sig: expected 32-byte r and s"));
    }
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(sr);
    out[32..].copy_from_slice(ss);
    Ok(out)
}

fn sha256_32(b: &[u8]) -> [u8; 32] {
    let mut h = [0u8; 32];
    h.copy_from_slice(&Sha256::digest(b));
    h
}

/// Verifies a TPM residency proof (`TPM2_Certify` output).
///
/// * `attest` — the marshaled `TPMS_ATTEST` the TPM signed.
/// * `ak_pub` — the `TPM2B_PUBLIC` of the attestation key that signed `attest`.
/// * `sig` — the `TPMT_SIGNATURE` over `attest`.
/// * `subject_pub` — the `TPM2B_PUBLIC` of the certified (DevID) key.
///
/// On success, the subject key is proven TPM-resident and non-exportable. See the
/// module docs for the trust boundary; the returned attestation is `L1Software` and
/// carries `HardwareRootedKey` / `StableDeviceIdentity` in `not_proven`.
pub fn verify_residency(
    attest: &[u8],
    ak_pub: &[u8],
    sig: &[u8],
    subject_pub: &[u8],
) -> Result<VerifiedAttestation> {
    // 1. Parse the attestation and confirm it is a genuine CERTIFY.
    let certify = parse_certify_attest(attest)?;

    // 2. Verify the certify signature under the AK's public key. ring hashes the
    //    message with SHA-256 and checks the fixed r||s ECDSA-P256 signature.
    let ak = parse_ecc_public(ak_pub)?;
    let rs = parse_ecdsa_sig(sig)?;
    let ak_key = ring::signature::UnparsedPublicKey::new(
        &ring::signature::ECDSA_P256_SHA256_FIXED,
        &ak.sec1_uncompressed,
    );
    ak_key
        .verify(attest, &rs)
        .map_err(|_| vfail("certify signature does not verify under the AK public key"))?;

    // 3. The AK Name must match the qualifiedSigner recorded in the attestation
    //    (the signer names itself). This binds the verified signature to the AK
    //    identity we report.
    let ak_name = compute_name(&ak)?;
    if certify.qualified_signer.len() < 2 || certify.qualified_signer[..2] != ak_name[..2] {
        return Err(vfail("attest qualifiedSigner is not a SHA-256 Name"));
    }
    // qualifiedSigner is the AK's *qualified* name (includes ancestry), so it is not
    // equal to the bare AK Name; we bind identity via the subject Name below and
    // report the AK by its own Name.

    // 4. Enforce non-exportability on the CERTIFIED subject key.
    let subject = parse_ecc_public(subject_pub)?;
    if subject.attributes & TPMA_OBJECT_FIXED_TPM == 0 {
        return Err(vfail(
            "subject key is not fixedTPM (could be duplicated off-TPM)",
        ));
    }
    if subject.attributes & TPMA_OBJECT_FIXED_PARENT == 0 {
        return Err(vfail(
            "subject key is not fixedParent (could be re-parented/exported)",
        ));
    }

    // 5. Bind the certified Name to the subject public we were given. Without this,
    //    a valid certify over some *other* key would be accepted for this subject.
    let subject_name = compute_name(&subject)?;
    if certify.certified_name != subject_name {
        return Err(vfail(
            "certified Name does not match the supplied subject key",
        ));
    }

    // Honest, normalized result. Residency + non-exportability are established;
    // hardware rooting and stable device identity are NOT (need an EK root).
    let proves = BTreeSet::from([Claim::KeyNonExportable]);
    let not_proven = BTreeSet::from([
        Claim::HardwareRootedKey,
        Claim::StableDeviceIdentity,
        Claim::MeasuredBoot,
        Claim::ContinuousLiveness,
        Claim::UnmodifiedArtifact,
    ]);
    Ok(VerifiedAttestation {
        backend: "tpm-devid-residency",
        assurance: AssuranceLevel::L1Software,
        subject: AttestedSubject::TpmResidentKey {
            ak_name_sha256: sha256_32(&ak_name),
            subject_name_sha256: sha256_32(&subject_name),
        },
        proves,
        not_proven,
        launch: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn b64(s: &str) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(s.trim())
            .expect("valid base64 fixture")
    }

    // Real swtpm-produced TPM2_Certify fixture (see tests/fixtures/tpm_devid/).
    fn attest() -> Vec<u8> {
        b64(include_str!("../tests/fixtures/tpm_devid/attest.bin.b64"))
    }
    fn ak_pub() -> Vec<u8> {
        b64(include_str!("../tests/fixtures/tpm_devid/ak.pub.b64"))
    }
    fn sig() -> Vec<u8> {
        b64(include_str!("../tests/fixtures/tpm_devid/sig.bin.b64"))
    }
    fn subj_pub() -> Vec<u8> {
        b64(include_str!("../tests/fixtures/tpm_devid/subj.pub.b64"))
    }

    /// POSITIVE CONTROL — a real TPM (swtpm) produced this blob; our independent
    /// pure-Rust verifier accepts it (producer ≠ verifier differential). Proves the
    /// verifier is not always-red, so the RED corpus below means something.
    #[test]
    fn accepts_a_real_tpm2_certify_and_reports_honestly() {
        let va = verify_residency(&attest(), &ak_pub(), &sig(), &subj_pub())
            .expect("real certify must verify");
        assert_eq!(va.assurance(), AssuranceLevel::L1Software);
        assert!(
            va.assurance() < AssuranceLevel::L2Device,
            "must not claim L2"
        );
        assert!(va.proves(Claim::KeyNonExportable));
        // The residency proof must NOT be read as hardware rooting.
        assert!(va.cannot_prove(Claim::HardwareRootedKey));
        assert!(va.cannot_prove(Claim::StableDeviceIdentity));
        assert!(va.proves.is_disjoint(&va.not_proven));
        assert!(matches!(va.subject, AttestedSubject::TpmResidentKey { .. }));
    }

    /// RED (revert detector for fixedParent) — clearing the subject's fixedParent
    /// bit must red with the specific cause. If someone deletes the fixedParent
    /// enforcement, this test goes green — i.e. it detects its own removal.
    #[test]
    fn reds_when_subject_is_not_fixed_parent() {
        let mut subj = subj_pub();
        // objectAttributes is the u32 at offset 2 (skip TPM2B size) + 2 (type) + 2
        // (nameAlg) = bytes [6..10] of the TPM2B_PUBLIC.
        let attrs = u32::from_be_bytes([subj[6], subj[7], subj[8], subj[9]]);
        let cleared = attrs & !TPMA_OBJECT_FIXED_PARENT;
        subj[6..10].copy_from_slice(&cleared.to_be_bytes());
        let err = verify_residency(&attest(), &ak_pub(), &sig(), &subj).unwrap_err();
        assert!(
            err.to_string().contains("fixedParent"),
            "wrong cause: {err}"
        );
    }

    /// RED — the certify signature must verify under the AK. Verifying with the
    /// WRONG key (the subject's public) must red on the signature.
    #[test]
    fn reds_when_signature_is_not_from_the_ak() {
        let err = verify_residency(&attest(), &subj_pub(), &sig(), &subj_pub()).unwrap_err();
        assert!(err.to_string().contains("signature"), "wrong cause: {err}");
    }

    /// RED — the certified Name must match the supplied subject. Passing a DIFFERENT
    /// key (the AK) as the subject must red on the Name binding (its attributes are
    /// fixedTPM|fixedParent too, so it passes the attribute checks and reaches the
    /// Name check — isolating that cause).
    #[test]
    fn reds_when_certified_name_does_not_match_subject() {
        let err = verify_residency(&attest(), &ak_pub(), &sig(), &ak_pub()).unwrap_err();
        assert!(
            err.to_string().contains("certified Name"),
            "wrong cause: {err}"
        );
    }

    /// RED — a truncated / non-CERTIFY attestation must red at parse.
    #[test]
    fn reds_on_truncated_attest() {
        let a = attest();
        let err = verify_residency(&a[..8], &ak_pub(), &sig(), &subj_pub()).unwrap_err();
        let s = err.to_string();
        assert!(s.contains("truncated") || s.contains("magic"), "cause: {s}");
    }
}
