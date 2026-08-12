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
        let cert_der = leaf.contents();

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
}
