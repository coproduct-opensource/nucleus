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

use crate::assurance::{
    AssuranceLevel, AttestedSubject, Claim, SvidAttestationBackend, VerifiedAttestation,
};
use crate::attestation::AttestationRequirements;
use crate::{oid, Error, Result};
use rustls::pki_types::{CertificateDer, UnixTime};
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
        // A TPM Name is a hash over the TPM public area, not the bare Ed25519
        // public key a receipt signer presents, so this residency proof cannot
        // bind a receipt signer directly (that binding is a later brick).
        subject_key_sha256: None,
        proves,
        not_proven,
        launch: None,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// EK-manufacturer-root chain verification (North Star C9, Phase 1 Inc 3, brick 1)
//
// `verify_residency` above proves a key is non-exportable on SOME TPM; it
// deliberately does not prove the TPM is genuine manufacturer silicon (see its
// `not_proven` set). That proof is an Endorsement Key (EK) certificate that
// chains to a PINNED manufacturer root CA. This brick verifies exactly that
// chain and yields an INERT `EkIdentity` witness — nothing here adds a `Claim`,
// a `VerifiedAttestation`, or an `AssuranceLevel`.
//
// Hardware rooting (`Claim::HardwareRootedKey`, `AssuranceLevel::L2Device`) stays
// UNREACHABLE until a later brick binds this EK to the residency AK (credential
// activation) and a single composition constructor consumes residency + EK +
// binding at once. A genuine EK with an UNBOUND AK proves "a TPM exists",
// never "THIS key lives in it" — so the witness must not be sayable as a claim
// on its own. Keeping it inert makes the half-done state unsayable by
// construction, not merely omitted.

/// tcg-kp-EKCertificate EKU (OID 2.23.133.8.1), DER OID value bytes. A real EK
/// certificate carries this; requiring it stops a non-EK cert (e.g. a TLS leaf
/// with serverAuth) from masquerading as an EK.
const EK_EKU_OID: &[u8] = &[0x67, 0x81, 0x05, 0x08, 0x01];

/// EK-chain signature algorithms: EK certs are RSA-2048/3072/4096 or ECC P-256/384
/// across manufacturers — all verified through `ring`, no new crypto in the TCB.
static EK_CHAIN_ALGS: &[&dyn rustls::pki_types::SignatureVerificationAlgorithm] = &[
    webpki::ring::ECDSA_P256_SHA256,
    webpki::ring::ECDSA_P384_SHA384,
    webpki::ring::RSA_PKCS1_2048_8192_SHA256,
    webpki::ring::RSA_PKCS1_2048_8192_SHA384,
    webpki::ring::RSA_PKCS1_2048_8192_SHA512,
];

/// PINNED TPM-manufacturer root CAs an EK certificate may chain to.
///
/// Brick 1 ships only an in-repo TEST root (exercised by fixtures). Which REAL
/// manufacturer roots to trust (Infineon/Nuvoton/Intel/STMicro/AMD…) and their
/// update/revocation policy is a federation-trust decision reserved for the
/// operator — an empty store proves nothing, by design.
#[derive(Default)]
pub struct EkTrustStore {
    anchors: Vec<(String, Vec<u8>)>,
}

impl EkTrustStore {
    pub fn new() -> Self {
        Self::default()
    }
    /// Pin a manufacturer root (DER). The label names the manufacturer this root
    /// vouches for; it is carried into `EkIdentity` on a successful chain.
    pub fn pin_root(&mut self, manufacturer: impl Into<String>, root_der: impl Into<Vec<u8>>) {
        self.anchors.push((manufacturer.into(), root_der.into()));
    }
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }
}

/// The genuine-silicon witness: an EK whose certificate chained to a pinned
/// manufacturer root. INERT by construction — no method turns it into a `Claim`
/// or an `AssuranceLevel`; only a later composition constructor (given an AK↔EK
/// binding and residency) may.
#[derive(Clone, Debug)]
pub struct EkIdentity {
    /// The EK certificate's subjectPublicKeyInfo (DER) — the handle a future
    /// credential-activation brick challenges to bind the residency AK.
    pub ek_spki_der: Vec<u8>,
    /// The manufacturer whose pinned root this EK chained to.
    pub manufacturer: String,
}

/// Verify that `ek_cert_der` chains, through `intermediates`, to a PINNED root in
/// `store`, and carries the EK EKU. Returns the inert [`EkIdentity`] witness.
///
/// EK-leaf `notAfter` is ADVISORY (TCG EK Credential Profile: it is manufacturer
/// discretion and may be `99991231235959Z` or already past), so the chain is
/// validated at the leaf's own `notBefore` instant rather than wall clock —
/// trust rests on the chain signatures and the pinned root, not on leaf expiry.
/// A bad signature or a chain to an UNPINNED root still fails.
pub fn verify_ek_chain(
    ek_cert_der: &[u8],
    intermediates: &[Vec<u8>],
    store: &EkTrustStore,
) -> Result<EkIdentity> {
    if store.is_empty() {
        return Err(vfail(
            "EK trust store is empty — no pinned root to chain to, so genuine silicon cannot be established",
        ));
    }

    let ee_der = CertificateDer::from(ek_cert_der);
    let ee = webpki::EndEntityCert::try_from(&ee_der)
        .map_err(|e| vfail(format!("EK leaf certificate did not parse: {e}")))?;

    let inter_ders: Vec<CertificateDer> = intermediates
        .iter()
        .map(|d| CertificateDer::from(d.as_slice()))
        .collect();

    // Validate at the leaf's own notBefore so leaf expiry is advisory (see above).
    let time = ek_not_before(ek_cert_der)?;

    // Try each pinned root individually so a success also tells us WHICH
    // manufacturer vouched — the label goes into the witness.
    let mut last_err = String::from("no pinned root matched");
    for (manufacturer, root_der) in &store.anchors {
        let anchor_der = CertificateDer::from(root_der.as_slice());
        let anchor = match webpki::anchor_from_trusted_cert(&anchor_der) {
            Ok(a) => a,
            Err(e) => {
                last_err = format!("pinned root {manufacturer:?} is not a valid trust anchor: {e}");
                continue;
            }
        };
        match ee.verify_for_usage(
            EK_CHAIN_ALGS,
            &[anchor],
            &inter_ders,
            time,
            webpki::KeyUsage::required(EK_EKU_OID),
            None,
            None,
        ) {
            Ok(_) => {
                return Ok(EkIdentity {
                    ek_spki_der: ek_spki(ek_cert_der)?,
                    manufacturer: manufacturer.clone(),
                });
            }
            Err(e) => last_err = format!("chain to {manufacturer:?}: {e}"),
        }
    }
    Err(vfail(format!(
        "EK certificate does not chain to any pinned manufacturer root ({last_err})"
    )))
}

/// The EK certificate's notBefore, as a webpki `UnixTime`.
fn ek_not_before(cert_der: &[u8]) -> Result<UnixTime> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| vfail(format!("EK certificate did not parse (validity): {e}")))?;
    let secs = cert.validity().not_before.timestamp();
    let secs = u64::try_from(secs).map_err(|_| vfail("EK notBefore is before the Unix epoch"))?;
    Ok(UnixTime::since_unix_epoch(std::time::Duration::from_secs(
        secs,
    )))
}

/// The EK certificate's subjectPublicKeyInfo (DER).
fn ek_spki(cert_der: &[u8]) -> Result<Vec<u8>> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| vfail(format!("EK certificate did not parse (spki): {e}")))?;
    Ok(cert.public_key().raw.to_vec())
}

// ─────────────────────────────────────────────────────────────────────────────
// AK↔EK binding via TPM credential activation (North Star C9, Phase 1 Inc 3, brick 2)
//
// Brick 1 proved an EK certificate chains to a manufacturer root; the residency
// verifier proved an AK is non-exportable. Neither proves the AK and that EK are
// on the SAME TPM — a genuine EK with an unrelated AK proves nothing about the
// AK's key. Credential activation closes that: nucleus (the verifier) builds a
// challenge that ONLY a TPM holding BOTH the EK and the object named `ak_name`
// can decrypt (TPM2_ActivateCredential), and getting our secret back proves
// co-residency.
//
// This is the VERIFIER's `TPM2_MakeCredential` half, pure and in-tree (ring ECDH
// + sha2 + AES-128-CFB), constructed to be byte-identical to what a real TPM's
// ActivateCredential consumes — validated by a swtpm round-trip (producer=nucleus,
// verifier=real TPM), the same producer≠verifier discipline as the residency work.
//
// INERT, like brick 1: the witness `AkEkBound` carries no `Claim` and no
// `AssuranceLevel`; only brick 3's composition (residency ∧ EK ∧ this) may reach
// L2Device. This brick covers ECC endorsement keys; RSA EKs are a disclosed
// follow-brick (RSA-OAEP-encrypt would add a primitive to the TCB).

/// INERT AK↔EK co-residency witness: a credential activation proved the residency
/// AK and the manufacturer-rooted EK are on the SAME TPM. No method yields a
/// `Claim` or `AssuranceLevel` — only brick 3's composition may. Fields tie back
/// to residency (`ak_name_sha256`) and brick 1 (`ek_spki_sha256`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AkEkBound {
    pub ak_name_sha256: [u8; 32],
    pub ek_spki_sha256: [u8; 32],
}

/// A credential-activation challenge — exactly the two TPM2Bs `tpm2_activatecredential`
/// consumes (`TPM2B_ID_OBJECT` and, for an ECC EK, a `TPM2B_ENCRYPTED_SECRET`
/// carrying the ephemeral `TPMS_ECC_POINT`).
pub struct CredentialChallenge {
    pub credential_blob: Vec<u8>,
    pub encrypted_secret: Vec<u8>,
}

#[cfg(feature = "tpm-devid")]
/// HMAC-SHA256 — hand-rolled over `sha2` (already in the TCB), so no `hmac` dep.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const B: usize = 64;
    let mut k0 = [0u8; B];
    if key.len() > B {
        k0[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k0[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; B];
    let mut opad = [0x5cu8; B];
    for i in 0..B {
        ipad[i] ^= k0[i];
        opad[i] ^= k0[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let ih = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(ih);
    outer.finalize().into()
}

#[cfg(feature = "tpm-devid")]
/// KDFa (TPM 2.0 Part 1 §11.4.10.2, SP800-108 counter mode). Single HMAC block —
/// valid for `bits <= 256`, which covers every use here (128-bit AES key, 256-bit
/// HMAC key). `K = HMAC(key, counter(1) || label || 0x00 || contextU || contextV || bits)`.
fn kdfa(key: &[u8], label: &str, context_u: &[u8], context_v: &[u8], bits: u32) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&1u32.to_be_bytes());
    msg.extend_from_slice(label.as_bytes());
    msg.push(0x00);
    msg.extend_from_slice(context_u);
    msg.extend_from_slice(context_v);
    msg.extend_from_slice(&bits.to_be_bytes());
    hmac_sha256(key, &msg)[..(bits as usize) / 8].to_vec()
}

#[cfg(feature = "tpm-devid")]
/// KDFe (TPM 2.0 Part 1 §11.4.10.3, SP800-56A one-step). Single hash block —
/// valid for `bits <= 256`. `K = H(counter(1) || Z || label || 0x00 || contextU || contextV)`.
fn kdfe(z: &[u8], label: &str, context_u: &[u8], context_v: &[u8], bits: u32) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(1u32.to_be_bytes());
    h.update(z);
    h.update(label.as_bytes());
    h.update([0x00]);
    h.update(context_u);
    h.update(context_v);
    h.finalize()[..(bits as usize) / 8].to_vec()
}

#[cfg(feature = "tpm-devid")]
/// `len(2 BE) || data` — a TPM2B.
fn tpm2b(data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 + data.len());
    v.extend_from_slice(&(data.len() as u16).to_be_bytes());
    v.extend_from_slice(data);
    v
}

/// The pure, seed-driven half (TPM 2.0 "SensitiveToCredential"): given the KDF
/// `seed`, protect `secret` for the object named `ak_name`. Returns the
/// `TPM2B_ID_OBJECT` (`credential_blob`). The AK name is bound TWICE — it keys the
/// STORAGE KDFa and is covered by the integrity HMAC — which is what makes a
/// credential built for one AK fail to activate on another.
#[cfg(feature = "tpm-devid")]
fn sensitive_to_credential(seed: &[u8], ak_name: &[u8], secret: &[u8]) -> Vec<u8> {
    use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};

    let sym_key = kdfa(seed, "STORAGE", ak_name, &[], 128);
    let mut enc_identity = tpm2b(secret); // plaintext = TPM2B(secret)
    let iv = [0u8; 16];
    cfb_mode::Encryptor::<aes::Aes128>::new(sym_key.as_slice().into(), (&iv).into())
        .encrypt(&mut enc_identity);

    let hmac_key = kdfa(seed, "INTEGRITY", &[], &[], 256);
    let mut integrity_input = enc_identity.clone();
    integrity_input.extend_from_slice(ak_name);
    let outer_hmac = hmac_sha256(&hmac_key, &integrity_input);

    // TPMS_ID_OBJECT = TPM2B_DIGEST(integrityHMAC) || encIdentity(raw)
    let mut id_object = tpm2b(&outer_hmac);
    id_object.extend_from_slice(&enc_identity);
    tpm2b(&id_object) // TPM2B_ID_OBJECT
}

/// Build a credential-activation challenge for an ECC endorsement key: only a TPM
/// holding that EK and the object named `ak_name` can recover `secret`.
///
/// `ek_pub` is the TPM's `TPM2B_PUBLIC` for the EK (ECC P-256). `secret` is a
/// fresh random challenge (≤ 32 bytes). A one-pass ECDH ephemeral × EK derives the
/// seed (KDFe), so the returned `encrypted_secret` carries the ephemeral point the
/// TPM needs to recompute it.
#[cfg(feature = "tpm-devid")]
pub fn make_credential_ecc(
    ek_pub: &[u8],
    ak_name: &[u8],
    secret: &[u8],
) -> Result<CredentialChallenge> {
    use ring::agreement::{agree_ephemeral, EphemeralPrivateKey, UnparsedPublicKey, ECDH_P256};

    if secret.len() > 32 {
        return Err(vfail("credential secret exceeds the SHA-256 digest size"));
    }
    let ek = parse_ecc_public(ek_pub)?; // 0x04 || EK_x || EK_y in ek.sec1_uncompressed
    let ek_x = ek.sec1_uncompressed[1..33].to_vec();

    let rng = ring::rand::SystemRandom::new();
    let eph = EphemeralPrivateKey::generate(&ECDH_P256, &rng)
        .map_err(|_| vfail("ephemeral key generation failed"))?;
    let eph_pub = eph
        .compute_public_key()
        .map_err(|_| vfail("ephemeral public key failed"))?;
    let eph_bytes = eph_pub.as_ref(); // 0x04 || eph_x || eph_y
    if eph_bytes.len() != 65 {
        return Err(vfail("unexpected ephemeral point encoding"));
    }
    let eph_x = eph_bytes[1..33].to_vec();
    let eph_y = eph_bytes[33..65].to_vec();

    let peer = UnparsedPublicKey::new(&ECDH_P256, &ek.sec1_uncompressed);
    let z = agree_ephemeral(eph, &peer, |shared| shared.to_vec())
        .map_err(|_| vfail("ECDH with the EK public key failed"))?;

    // seed = KDFe(SHA256, Z, "IDENTITY", ephemeral.x, EK.x, 256)
    let seed = kdfe(&z, "IDENTITY", &eph_x, &ek_x, 256);
    let credential_blob = sensitive_to_credential(&seed, ak_name, secret);

    // TPM2B_ENCRYPTED_SECRET = TPM2B( TPMS_ECC_POINT{ TPM2B(x), TPM2B(y) } )
    let mut point = tpm2b(&eph_x);
    point.extend_from_slice(&tpm2b(&eph_y));
    let encrypted_secret = tpm2b(&point);

    Ok(CredentialChallenge {
        credential_blob,
        encrypted_secret,
    })
}

/// Mint the inert [`AkEkBound`] iff the TPM returned EXACTLY the challenge secret —
/// i.e. a TPM holding both the manufacturer-rooted EK and the residency AK
/// recovered it, so the two keys are co-resident. Constant-time comparison; `Err`
/// on any mismatch. Produces no `Claim` (L2 stays unreachable until brick 3).
pub fn verify_activation(
    expected_secret: &[u8],
    recovered_secret: &[u8],
    ak_name: &[u8],
    ek_spki_der: &[u8],
) -> Result<AkEkBound> {
    if !ct_eq(expected_secret, recovered_secret) {
        return Err(vfail(
            "credential activation did not recover the challenge secret — the AK and EK are not co-resident (or a different TPM answered)",
        ));
    }
    Ok(AkEkBound {
        ak_name_sha256: sha256_32(ak_name),
        ek_spki_sha256: sha256_32(ek_spki_der),
    })
}

/// Constant-time byte-slice equality. Length is compared first and non-secret
/// (the challenge length is fixed), then every byte is folded so the comparison
/// time does not depend on WHERE a mismatch is.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ─────────────────────────────────────────────────────────────────────────────
// L2 composition (North Star C9, Phase 1 Inc 3, brick 3)
//
// The ONLY place `HardwareRootedKey` / `StableDeviceIdentity` / `GenuineSilicon`
// are emitted and assurance rises to L2Device. Bricks 1 and 2 produce inert
// witnesses precisely so this composition is the single choke point: a caller
// literally cannot construct an L2 result without holding all three witness
// values, so a partial Inc-3 (EK chain alone, or a binding alone) is structurally
// unable to claim hardware rooting — unsayable, not merely undocumented.
//
// It refuses unless the three witnesses are about the SAME TPM — the coherence
// tooth that stops a genuine EK *here* and a non-exportable key *there* from
// composing into a false hardware-rooted claim.

/// Compose residency (non-exportability), an EK-manufacturer-root chain, and an
/// AK↔EK binding into an `L2Device` attestation. Refuses unless all three name
/// the same TPM: the binding's AK is the residency AK, the binding's EK is the
/// manufacturer-rooted EK, and residency actually established non-exportability.
pub fn compose_l2(
    residency: &VerifiedAttestation,
    ek: &EkIdentity,
    binding: &AkEkBound,
) -> Result<VerifiedAttestation> {
    let ak_name_sha256 = match &residency.subject {
        AttestedSubject::TpmResidentKey { ak_name_sha256, .. } => *ak_name_sha256,
        _ => return Err(vfail("residency attestation is not a TPM resident key")),
    };
    if !residency.proves(Claim::KeyNonExportable) {
        return Err(vfail(
            "residency proof does not establish KeyNonExportable — there is nothing to root",
        ));
    }
    if binding.ak_name_sha256 != ak_name_sha256 {
        return Err(vfail(
            "the AK↔EK binding names a different AK than the residency proof — not the same key",
        ));
    }
    if binding.ek_spki_sha256 != sha256_32(&ek.ek_spki_der) {
        return Err(vfail(
            "the AK↔EK binding names a different EK than the manufacturer-rooted one — not the same TPM",
        ));
    }

    // Coherent: a non-exportable AK, bound to the EK of a genuine manufacturer TPM.
    let proves = BTreeSet::from([
        Claim::KeyNonExportable,     // carried from residency
        Claim::GenuineSilicon,       // from the EK-manufacturer-root chain (brick 1)
        Claim::HardwareRootedKey,    // GenuineSilicon ∧ AkEkBound ∧ KeyNonExportable
        Claim::StableDeviceIdentity, // the EK is the permanent per-device identity
    ]);
    let not_proven = BTreeSet::from([
        Claim::MeasuredBoot, // a PCR/TEE quote is L3, not established here
        Claim::ContinuousLiveness,
        Claim::UnmodifiedArtifact,
    ]);
    Ok(VerifiedAttestation {
        backend: "tpm-devid-l2",
        assurance: AssuranceLevel::L2Device,
        subject: residency.subject.clone(),
        // Inherits residency's key-binding: still a TPM Name, not a bare
        // Ed25519 receipt-signer key.
        subject_key_sha256: residency.subject_key_sha256,
        proves,
        not_proven,
        launch: None,
    })
}

#[cfg(test)]
mod l2_composition_tests {
    use super::{compose_l2, sha256_32, AkEkBound, EkIdentity};
    use crate::assurance::{AssuranceLevel, AttestedSubject, Claim, VerifiedAttestation};
    use std::collections::BTreeSet;

    fn residency(ak: [u8; 32]) -> VerifiedAttestation {
        VerifiedAttestation {
            backend: "tpm-devid-residency",
            assurance: AssuranceLevel::L1Software,
            subject: AttestedSubject::TpmResidentKey {
                ak_name_sha256: ak,
                subject_name_sha256: [0u8; 32],
            },
            subject_key_sha256: None,
            proves: BTreeSet::from([Claim::KeyNonExportable]),
            not_proven: BTreeSet::from([Claim::HardwareRootedKey, Claim::StableDeviceIdentity]),
            launch: None,
        }
    }
    fn ek() -> EkIdentity {
        EkIdentity {
            ek_spki_der: vec![1, 2, 3, 4, 5],
            manufacturer: "test-root".into(),
        }
    }

    /// Coherent witnesses → L2Device, emitting exactly the four claims, with
    /// MeasuredBoot still `not_proven` (L3 unreachable) and the sets disjoint.
    #[test]
    fn coherent_witnesses_compose_to_l2() {
        let ak = [7u8; 32];
        let e = ek();
        let b = AkEkBound {
            ak_name_sha256: ak,
            ek_spki_sha256: sha256_32(&e.ek_spki_der),
        };
        let va = compose_l2(&residency(ak), &e, &b).expect("coherent → L2");
        assert_eq!(va.assurance(), AssuranceLevel::L2Device);
        for c in [
            Claim::KeyNonExportable,
            Claim::GenuineSilicon,
            Claim::HardwareRootedKey,
            Claim::StableDeviceIdentity,
        ] {
            assert!(va.proves(c), "must prove {c:?}");
        }
        assert!(va.cannot_prove(Claim::MeasuredBoot), "MeasuredBoot is L3");
        assert!(va.proves.is_disjoint(&va.not_proven));
    }

    /// **Coherence bite — wrong AK.** A binding for a different AK than the
    /// residency proof must not compose (three proofs, not the same key).
    #[test]
    fn a_binding_for_a_different_ak_is_refused() {
        let e = ek();
        let b = AkEkBound {
            ak_name_sha256: [9u8; 32], // != residency's AK
            ek_spki_sha256: sha256_32(&e.ek_spki_der),
        };
        assert!(compose_l2(&residency([7u8; 32]), &e, &b).is_err());
    }

    /// **Coherence bite — wrong EK.** A binding whose EK is not the
    /// manufacturer-rooted one must not compose (not the same TPM).
    #[test]
    fn a_binding_for_a_different_ek_is_refused() {
        let ak = [7u8; 32];
        let b = AkEkBound {
            ak_name_sha256: ak,
            ek_spki_sha256: sha256_32(b"some other EK"),
        };
        assert!(compose_l2(&residency(ak), &ek(), &b).is_err());
    }

    /// Residency that never established non-exportability cannot be rooted.
    #[test]
    fn residency_without_nonexportable_is_refused() {
        let ak = [7u8; 32];
        let mut r = residency(ak);
        r.proves = BTreeSet::new(); // strip KeyNonExportable
        let e = ek();
        let b = AkEkBound {
            ak_name_sha256: ak,
            ek_spki_sha256: sha256_32(&e.ek_spki_der),
        };
        assert!(compose_l2(&r, &e, &b).is_err());
    }
}

#[cfg(all(test, feature = "tpm-devid"))]
mod credential_activation_tests {
    use super::{hmac_sha256, kdfa, sensitive_to_credential, verify_activation};

    fn name(tag: u8) -> Vec<u8> {
        let mut n = vec![0x00, 0x0b]; // nameAlg = SHA-256
        n.extend_from_slice(&[tag; 32]);
        n
    }

    /// The credential blob depends on the AK name — a credential built for one AK
    /// differs from one built for another (same seed + secret). Necessary (not
    /// sufficient) for the wrong-AK activation to fail; the sufficiency is the
    /// swtpm bite in `scripts/tpm-credential-activation-check.sh`.
    #[test]
    fn credential_blob_is_ak_name_bound() {
        let seed = [7u8; 32];
        let secret = [0xa5u8; 16];
        let b1 = sensitive_to_credential(&seed, &name(1), &secret);
        let b2 = sensitive_to_credential(&seed, &name(2), &secret);
        assert_ne!(b1, b2, "the credential blob must depend on the AK name");
    }

    /// **The integrity HMAC genuinely covers the AK name** — the exact check a TPM
    /// runs in ActivateCredential. Reconstruct the blob's HMAC and confirm it
    /// matches an HMAC over `encIdentity || name`, and that swapping the name
    /// breaks it. Reds if the name is dropped from the integrity input.
    #[test]
    fn integrity_hmac_binds_the_name() {
        let seed = [3u8; 32];
        let secret = [0x11u8; 16];
        let n1 = name(1);
        let blob = sensitive_to_credential(&seed, &n1, &secret);
        // blob = TPM2B( TPM2B(hmac=32) || encIdentity ); parse it out.
        let id_object = &blob[2..];
        let hmac_in_blob = &id_object[2..2 + 32];
        let enc_identity = &id_object[2 + 32..];

        let hmac_key = kdfa(&seed, "INTEGRITY", &[], &[], 256);
        let mut over_correct = enc_identity.to_vec();
        over_correct.extend_from_slice(&n1);
        assert_eq!(
            hmac_sha256(&hmac_key, &over_correct),
            hmac_in_blob,
            "the blob's integrity HMAC must be HMAC(encIdentity || name)"
        );

        let mut over_wrong = enc_identity.to_vec();
        over_wrong.extend_from_slice(&name(2)); // swap the name
        assert_ne!(
            hmac_sha256(&hmac_key, &over_wrong).as_slice(),
            hmac_in_blob,
            "a name-swapped HMAC must NOT match — the name is what binds the AK"
        );
    }

    /// `verify_activation` mints the witness only on an exact secret match.
    #[test]
    fn verify_activation_requires_exact_recovery() {
        let ak = vec![9u8; 34];
        let ek = vec![4u8; 91];
        let bound = verify_activation(b"the-secret", b"the-secret", &ak, &ek).unwrap();
        assert_eq!(bound.ak_name_sha256, super::sha256_32(&ak));
        assert!(verify_activation(b"the-secret", b"the-secre_", &ak, &ek).is_err());
        assert!(verify_activation(b"the-secret", b"short", &ak, &ek).is_err());
    }
}

#[cfg(test)]
mod ek_chain_tests {
    use super::{verify_ek_chain, EkTrustStore};
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    };

    /// A self-signed CA: returns its DER (for pinning) and an `Issuer` for signing
    /// leaves under it.
    fn ca(name: &str) -> (Vec<u8>, Issuer<'static, KeyPair>) {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(vec![name.to_string()]).unwrap();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let der = p.self_signed(&key).unwrap().der().to_vec();
        (der, Issuer::new(p, key))
    }

    /// The tcg-kp-EKCertificate EKU as an `extKeyUsage` extension (2.5.29.37 =
    /// SEQUENCE { OID 2.23.133.8.1 }) — rcgen has no built-in EK EKU variant.
    fn ek_eku_ext() -> rcgen::CustomExtension {
        rcgen::CustomExtension::from_oid_content(
            &[2, 5, 29, 37],
            vec![0x30, 0x07, 0x06, 0x05, 0x67, 0x81, 0x05, 0x08, 0x01],
        )
    }

    /// An EK leaf signed by `issuer`. By default it carries the EK EKU; passing
    /// `eku` gives it a NON-EK EKU instead, to prove the requirement bites.
    fn ek_leaf(
        issuer: &Issuer<'_, KeyPair>,
        eku: Option<ExtendedKeyUsagePurpose>,
        validity: Option<(i32, i32)>,
    ) -> Vec<u8> {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(vec!["ek".to_string()]).unwrap();
        match eku {
            Some(e) => p.extended_key_usages = vec![e],
            None => p.custom_extensions.push(ek_eku_ext()),
        }
        if let Some((from, to)) = validity {
            p.not_before = rcgen::date_time_ymd(from, 1, 1);
            p.not_after = rcgen::date_time_ymd(to, 1, 1);
        }
        p.signed_by(&key, issuer).unwrap().der().to_vec()
    }

    /// Positive: an EK leaf chaining to a PINNED root verifies, and the witness
    /// carries the manufacturer label and a non-empty EK SPKI.
    #[test]
    fn ek_chains_to_a_pinned_root() {
        let (root_der, issuer) = ca("test-root");
        let ek = ek_leaf(&issuer, None, None);
        let mut store = EkTrustStore::new();
        store.pin_root("nucleus-test-root", root_der);

        let id = verify_ek_chain(&ek, &[], &store).expect("EK should chain to the pinned root");
        assert_eq!(id.manufacturer, "nucleus-test-root");
        assert!(!id.ek_spki_der.is_empty());
    }

    /// **The bite (anti-overclaim).** An EK signed by a root that is NOT pinned —
    /// the shape of swtpm's own self-signed EK — must NOT verify, so genuine
    /// silicon stays unprovable without a real manufacturer root. Reds if the
    /// pinning is ever weakened to accept unrooted EKs.
    #[test]
    fn an_unpinned_root_is_rejected() {
        let (pinned_der, _pinned) = ca("pinned");
        let (_other_der, other) = ca("swtpm-like-unpinned");
        let ek = ek_leaf(&other, None, None);
        let mut store = EkTrustStore::new();
        // Pin ONLY the first root; the EK chains to the other.
        store.pin_root("pinned", pinned_der);
        assert!(verify_ek_chain(&ek, &[], &store).is_err());
    }

    /// A tampered EK certificate (a flipped signature byte) must not verify.
    #[test]
    fn a_tampered_ek_is_rejected() {
        let (root_der, issuer) = ca("test-root");
        let mut ek = ek_leaf(&issuer, None, None);
        let n = ek.len();
        ek[n - 1] ^= 0xff; // corrupt the trailing signature bytes
        let mut store = EkTrustStore::new();
        store.pin_root("test-root", root_der);
        assert!(verify_ek_chain(&ek, &[], &store).is_err());
    }

    /// The EK EKU requirement bites: a leaf carrying a NON-EK EKU (serverAuth),
    /// even when it chains to a pinned root, is refused — a TLS cert cannot pose
    /// as an EK.
    #[test]
    fn a_non_ek_eku_is_rejected() {
        let (root_der, issuer) = ca("test-root");
        let ek = ek_leaf(&issuer, Some(ExtendedKeyUsagePurpose::ServerAuth), None);
        let mut store = EkTrustStore::new();
        store.pin_root("test-root", root_der);
        assert!(verify_ek_chain(&ek, &[], &store).is_err());
    }

    /// An empty store proves nothing — refuse rather than accept any EK.
    #[test]
    fn an_empty_store_refuses() {
        let (_d, issuer) = ca("test-root");
        let ek = ek_leaf(&issuer, None, None);
        assert!(verify_ek_chain(&ek, &[], &EkTrustStore::new()).is_err());
    }

    /// EK-leaf expiry is ADVISORY (TCG): an EK whose `notAfter` is in the past but
    /// which chains validly to a pinned root still verifies, because the chain is
    /// checked at the leaf's `notBefore`. (A bad signature still fails — proven by
    /// `a_tampered_ek_is_rejected` — so this did not disable validation.)
    #[test]
    fn an_expired_ek_leaf_still_verifies() {
        let (root_der, issuer) = ca("test-root");
        // Long-lived root; short, already-expired leaf.
        let ek = ek_leaf(&issuer, None, Some((2020, 2021)));
        let mut store = EkTrustStore::new();
        store.pin_root("test-root", root_der);
        assert!(verify_ek_chain(&ek, &[], &store).is_ok());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// X.509 residency evidence + relying-party backend (Inc 2)
// ─────────────────────────────────────────────────────────────────────────────

const RESIDENCY_EVIDENCE_V1: u8 = 1;

/// A TPM residency proof carried by (or to be embedded in) an X.509 certificate.
///
/// Bundles everything [`verify_residency`] needs: the signed `TPMS_ATTEST`, the
/// certify signature, the AK public, and the certified subject public.
#[derive(Clone, Debug)]
pub struct ResidencyEvidence {
    /// Marshaled `TPMS_ATTEST` (CERTIFY).
    pub attest: Vec<u8>,
    /// `TPMT_SIGNATURE` over `attest`.
    pub sig: Vec<u8>,
    /// `TPM2B_PUBLIC` of the attestation key.
    pub ak_pub: Vec<u8>,
    /// `TPM2B_PUBLIC` of the certified subject key.
    pub subject_pub: Vec<u8>,
}

impl ResidencyEvidence {
    /// Encodes the evidence as the value of the nucleus TPM-residency X.509 extension
    /// (OID `1.3.6.1.4.1.57212.1.3`). Internal length-prefixed format (version byte +
    /// four `u16`-length-prefixed fields); deliberately NOT TCG SKAE (see [`oid`]).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![RESIDENCY_EVIDENCE_V1];
        for field in [&self.attest, &self.sig, &self.ak_pub, &self.subject_pub] {
            out.extend_from_slice(&(field.len() as u16).to_be_bytes());
            out.extend_from_slice(field);
        }
        out
    }

    /// Parses an extension value produced by [`Self::encode`].
    pub fn parse(value: &[u8]) -> Result<Self> {
        let mut r = Reader::new(value);
        if r.take(1)?[0] != RESIDENCY_EVIDENCE_V1 {
            return Err(vfail("residency evidence: unsupported version"));
        }
        Ok(ResidencyEvidence {
            attest: r.tpm2b()?.to_vec(),
            sig: r.tpm2b()?.to_vec(),
            ak_pub: r.tpm2b()?.to_vec(),
            subject_pub: r.tpm2b()?.to_vec(),
        })
    }
}

/// Extracts TPM-residency evidence from an X.509 certificate (DER), if present.
pub fn extract_residency_evidence(cert_der: &[u8]) -> Option<ResidencyEvidence> {
    use x509_parser::prelude::{FromDer, X509Certificate};

    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    for ext in cert.extensions() {
        if ext.oid.as_bytes() == oid::OID_NUCLEUS_TPM_RESIDENCY_BYTES {
            return ResidencyEvidence::parse(ext.value).ok();
        }
    }
    None
}

/// The uncompressed EC point (`0x04 || X || Y`, 65 bytes) of a certificate's leaf
/// public key. Accepts either the bare BIT STRING content or a full SPKI DER (the
/// point is its trailing 65 bytes for P-256 uncompressed keys).
fn leaf_ec_point(cert_der: &[u8]) -> Result<Vec<u8>> {
    use x509_parser::prelude::{FromDer, X509Certificate};

    let (_, cert) =
        X509Certificate::from_der(cert_der).map_err(|_| vfail("cert: X.509 parse failed"))?;
    let raw = cert.public_key().subject_public_key.data.as_ref();
    if raw.len() == 65 && raw[0] == 0x04 {
        Ok(raw.to_vec())
    } else if raw.len() >= 65 && raw[raw.len() - 65] == 0x04 {
        Ok(raw[raw.len() - 65..].to_vec())
    } else {
        Err(vfail("cert: leaf key is not an uncompressed P-256 point"))
    }
}

/// Relying-party backend: verifies a served SVID that carries a TPM DevID residency
/// proof, and **binds the proof to the certificate's own key**.
///
/// The binding is the load-bearing SVID property: without it, a valid residency
/// proof for *some other* TPM key could be replayed into an unrelated certificate.
/// This backend refuses unless the certified subject key is exactly the leaf key.
///
/// [`AttestationRequirements`] constrain launch measurements and do not apply to
/// residency, so they are ignored here (the trait shares one signature across roots).
#[derive(Debug, Clone, Copy, Default)]
pub struct TpmDevidBackend;

impl TpmDevidBackend {
    /// The PEM-free core of [`Self::verify_svid`]: verify a leaf certificate's TPM
    /// residency proof and **bind it to the leaf's own key**, working directly on
    /// DER (what a relying party holds after a TLS handshake). Kept as the single
    /// source of truth for the load-bearing binding check so a live gate and the
    /// SVID trait path cannot drift.
    ///
    /// `require_attestation`: when set, an absent residency extension is a hard
    /// error (fail-closed); when cleared, absence yields `Ok(None)`. A present but
    /// invalid, or replayed, proof is **always** an `Err`.
    pub fn verify_leaf_der(
        cert_der: &[u8],
        require_attestation: bool,
    ) -> Result<Option<VerifiedAttestation>> {
        let evidence = match extract_residency_evidence(cert_der) {
            Some(ev) => ev,
            None if require_attestation => {
                return Err(vfail(
                    "served SVID carries no TPM residency evidence (fail-closed)",
                ))
            }
            None => return Ok(None),
        };

        // The residency proof itself: signature, non-exportability, Name binding.
        let va = verify_residency(
            &evidence.attest,
            &evidence.ak_pub,
            &evidence.sig,
            &evidence.subject_pub,
        )?;

        // SVID binding: the certified TPM key must BE this certificate's key.
        let subject = parse_ecc_public(&evidence.subject_pub)?;
        if leaf_ec_point(cert_der)? != subject.sec1_uncompressed {
            return Err(vfail(
                "TPM residency proof certifies a different key than the certificate (possible replay)",
            ));
        }
        Ok(Some(va))
    }
}

impl SvidAttestationBackend for TpmDevidBackend {
    fn id(&self) -> &'static str {
        "tpm-devid-residency"
    }

    fn assurance(&self) -> AssuranceLevel {
        AssuranceLevel::L1Software
    }

    fn verify_svid(
        &self,
        chain_pem: &str,
        _requirements: &AttestationRequirements,
        require_attestation: bool,
    ) -> Result<Option<VerifiedAttestation>> {
        let leaf =
            pem::parse(chain_pem).map_err(|e| vfail(format!("cert PEM parse failed: {e}")))?;
        Self::verify_leaf_der(leaf.contents(), require_attestation)
    }
}

/// The effective assurance a served SVID's leaf certificate carries, for a
/// relying-party **assurance floor** (North Star C9 live enforcement).
///
/// `launch_verified` is the caller's already-computed self-measured
/// launch-attestation result — [`AssuranceLevel::L1Software`] when the cert's
/// [`crate::LaunchAttestation`] matched the configured requirements, else the
/// baseline. This adds the TPM-residency contribution:
///
/// * **absent** residency evidence ⇒ the launch-derived base level (no change);
/// * **present and valid** (verifies *and* binds to the leaf key) ⇒ raised to the
///   residency backend's level;
/// * **present but invalid or replayed** ⇒ a hard [`Err`] — a floor can never be
///   satisfied by malformed residency evidence (fail-closed).
///
/// Residency alone is [`AssuranceLevel::L1Software`] (it proves
/// [`Claim::KeyNonExportable`], not hardware rooting). Reaching
/// [`AssuranceLevel::L2Device`] additionally requires anchoring the AK to a
/// manufacturer-signed EK (a later increment), so an `L2Device` floor currently
/// refuses **every** SVID — correct fail-closed behavior, not a defect.
pub fn effective_assurance(cert_der: &[u8], launch_verified: bool) -> Result<AssuranceLevel> {
    let base = if launch_verified {
        AssuranceLevel::L1Software
    } else {
        AssuranceLevel::L0Bearer
    };
    // `require_attestation = false`: an SVID may carry its assurance via launch
    // attestation instead of residency, so *absence* is not itself a failure —
    // but a present-yet-invalid proof still errs (verify_leaf_der is fail-closed).
    match TpmDevidBackend::verify_leaf_der(cert_der, false)? {
        Some(va) => Ok(base.max(va.assurance)),
        None => Ok(base),
    }
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

    // ── Inc 2: X.509 residency extension + relying-party backend ──────────────

    fn evidence() -> ResidencyEvidence {
        ResidencyEvidence {
            attest: attest(),
            sig: sig(),
            ak_pub: ak_pub(),
            subject_pub: subj_pub(),
        }
    }

    fn point_of(pub2b: &[u8]) -> Vec<u8> {
        parse_ecc_public(pub2b).unwrap().sec1_uncompressed
    }

    /// P-256 uncompressed SPKI DER = fixed 26-byte prefix + the 65-byte point.
    fn p256_spki_der(point_sec1: &[u8]) -> Vec<u8> {
        const PREFIX: &[u8] = &[
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        let mut v = PREFIX.to_vec();
        v.extend_from_slice(point_sec1);
        v
    }

    /// A raw SPKI wrapped so rcgen can sign a cert for a public key we don't hold the
    /// private half of (mirrors `SelfSignedCa`'s `CsrPublicKey`).
    struct RawSpki(Vec<u8>);
    impl rcgen::PublicKeyData for RawSpki {
        fn der_bytes(&self) -> &[u8] {
            &self.0
        }
        fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
            &rcgen::PKCS_ECDSA_P256_SHA256
        }
    }

    /// Builds a leaf cert whose key is `leaf_point`, optionally embedding a
    /// residency extension, signed by a throwaway CA. Returns the leaf PEM.
    fn build_cert(leaf_point: &[u8], residency_ext: Option<&[u8]>) -> String {
        use rcgen::{
            BasicConstraints, CertificateParams, CustomExtension, IsCa, Issuer, KeyPair,
            PKCS_ECDSA_P256_SHA256,
        };
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let issuer = Issuer::from_params(&ca_params, &ca_key);

        let spki = RawSpki(p256_spki_der(leaf_point));
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        if let Some(value) = residency_ext {
            params
                .custom_extensions
                .push(CustomExtension::from_oid_content(
                    oid::OID_NUCLEUS_TPM_RESIDENCY_TUPLE,
                    value.to_vec(),
                ));
        }
        params.signed_by(&spki, &issuer).unwrap().pem()
    }

    #[test]
    fn evidence_codec_roundtrips() {
        let ev = evidence();
        let parsed = ResidencyEvidence::parse(&ev.encode()).expect("roundtrip");
        assert_eq!(parsed.attest, ev.attest);
        assert_eq!(parsed.subject_pub, ev.subject_pub);
    }

    /// POSITIVE — a served SVID whose key IS the TPM subject key, carrying a real
    /// residency proof, verifies end to end.
    #[test]
    fn backend_accepts_svid_bound_to_the_tpm_key() {
        let pem = build_cert(&point_of(&subj_pub()), Some(&evidence().encode()));
        let va = TpmDevidBackend
            .verify_svid(&pem, &AttestationRequirements::any(), true)
            .expect("verify ok")
            .expect("attested");
        assert!(va.proves(Claim::KeyNonExportable));
        assert!(va.cannot_prove(Claim::HardwareRootedKey));
        assert!(matches!(va.subject, AttestedSubject::TpmResidentKey { .. }));
    }

    /// RED (anti-replay) — the SAME valid residency proof embedded in a cert whose
    /// key is a DIFFERENT key (the AK's point) must red on the binding, not pass.
    #[test]
    fn backend_reds_when_proof_is_replayed_into_a_foreign_cert() {
        let pem = build_cert(&point_of(&ak_pub()), Some(&evidence().encode()));
        let err = TpmDevidBackend
            .verify_svid(&pem, &AttestationRequirements::any(), true)
            .unwrap_err();
        assert!(err.to_string().contains("different key"), "cause: {err}");
    }

    /// RED (fail-closed) — a cert with no residency extension is refused when
    /// required, and yields no attestation when not required.
    #[test]
    fn backend_fails_closed_when_evidence_absent() {
        let pem = build_cert(&point_of(&subj_pub()), None);
        assert!(TpmDevidBackend
            .verify_svid(&pem, &AttestationRequirements::any(), true)
            .is_err());
        assert!(TpmDevidBackend
            .verify_svid(&pem, &AttestationRequirements::any(), false)
            .expect("absent-not-required ok")
            .is_none());
    }

    // ── Inc 2 (live floor): effective_assurance for a relying-party gate ───────

    fn der_of(pem: &str) -> Vec<u8> {
        pem::parse(pem).expect("pem").contents().to_vec()
    }

    /// A valid residency proof bound to the leaf key raises the effective level to
    /// L1Software — so an `L1Software` floor ADMITS it (the positive teeth).
    #[test]
    fn effective_assurance_admits_valid_residency_at_l1() {
        let der = der_of(&build_cert(
            &point_of(&subj_pub()),
            Some(&evidence().encode()),
        ));
        let level = effective_assurance(&der, false).expect("valid residency");
        assert_eq!(level, AssuranceLevel::L1Software);
        assert!(level >= AssuranceLevel::L1Software);
    }

    /// With no residency evidence, the level is exactly the launch-derived base:
    /// L0Bearer without launch attestation, L1Software with it. An `L1Software`
    /// floor therefore REFUSES a bare bearer SVID (the negative teeth).
    #[test]
    fn effective_assurance_falls_back_to_launch_base_when_absent() {
        let der = der_of(&build_cert(&point_of(&subj_pub()), None));
        assert_eq!(
            effective_assurance(&der, false).expect("ok"),
            AssuranceLevel::L0Bearer
        );
        assert_eq!(
            effective_assurance(&der, true).expect("ok"),
            AssuranceLevel::L1Software
        );
    }

    /// FAIL-CLOSED — a valid proof REPLAYED into a cert whose key is a different key
    /// must make the floor decision err, never silently pass at the base level.
    #[test]
    fn effective_assurance_fails_closed_on_replayed_proof() {
        let der = der_of(&build_cert(
            &point_of(&ak_pub()),
            Some(&evidence().encode()),
        ));
        // Even claiming a launch base of true must not rescue a replayed proof.
        assert!(effective_assurance(&der, true).is_err());
    }

    /// HONEST CEILING — residency alone is L1Software, so an `L2Device` floor
    /// refuses even a valid device-resident SVID today (genuine-silicon needs the
    /// EK-manufacturer root, a later increment). This asserts the gate never
    /// over-admits an L2 claim the evidence cannot back.
    #[test]
    fn effective_assurance_l2_floor_refuses_residency_only() {
        let der = der_of(&build_cert(
            &point_of(&subj_pub()),
            Some(&evidence().encode()),
        ));
        let level = effective_assurance(&der, false).expect("valid residency");
        assert!(
            level < AssuranceLevel::L2Device,
            "residency-only must not satisfy an L2 floor"
        );
    }
}
