//! A TPM-resident ECC P-256 signing key that the TPM uses only while the boot
//! PCRs hold the values they held when it was created (ADR 0012).
//!
//! The key is created under a storage primary in the OWNER hierarchy, derived
//! from a fixed template, so the same TPM re-derives the same parent on every
//! boot and nothing about the parent is stored. The key's `authPolicy` is
//! `PolicyPCR` over [`crate::key_attestation::BOOT_POLICY_PCRS`] at the
//! values read when it is created, and `userWithAuth` is clear, so the only
//! way to use it is a policy session that has run `PolicyPCR` while the PCRs
//! still hold those values. What the disk holds is the TPM's own wrapping of
//! the private key ([`WrappedKey`]): it loads only under this TPM's parent,
//! and signs only in this boot state.
//!
//! The same raw command layer as the quote ([`crate::attester`]): `Create`,
//! `Load`, `StartAuthSession`, `PolicyPCR`, `Sign`, `Certify` and
//! `PCR_Extend`, with password and policy sessions. No `libtss2`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use crate::attester::{
    AttestError, Attester, DeviceTransport, Session, SocketTransport, Tpm, Transport,
};
use crate::key_attestation::{
    CustodyStatement, EccP256Public, FEDERATION_KEY_ATTRIBUTES, TpmCustodyStatement,
    certify_qualifying_data, pcr_selection_bytes, policy_pcr_digest,
};
use crate::wire::Reader;

const TPM_RH_OWNER: u32 = 0x4000_0001;
const TPM_RH_NULL: u32 = 0x4000_0007;
const TPM_SE_POLICY: u8 = 0x01;
const TPM_ST_HASHCHECK: u16 = 0x8024;

const TPM_ALG_SHA256: u16 = 0x000B;
const TPM_ALG_AES: u16 = 0x0006;
const TPM_ALG_NULL: u16 = 0x0010;
const TPM_ALG_ECDSA: u16 = 0x0018;
const TPM_ALG_ECC: u16 = 0x0023;
const TPM_ALG_CFB: u16 = 0x0043;
const TPM_ECC_NIST_P256: u16 = 0x0003;

const CC_CERTIFY: u32 = 0x0000_0148;
const CC_CREATE: u32 = 0x0000_0153;
const CC_LOAD: u32 = 0x0000_0157;
const CC_SIGN: u32 = 0x0000_015D;
const CC_START_AUTH_SESSION: u32 = 0x0000_0176;
const CC_POLICY_PCR: u32 = 0x0000_017F;
const CC_PCR_EXTEND: u32 = 0x0000_0182;

/// `fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | noDA |
/// restricted | decrypt`: a storage key.
const STORAGE_PRIMARY_ATTRIBUTES: u32 = 0x0003_0472;

fn tpm2b(out: &mut Vec<u8>, b: &[u8]) -> Result<(), AttestError> {
    let n = u16::try_from(b.len()).map_err(|_| AttestError::Other("TPM2B too long".into()))?;
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(b);
    Ok(())
}

/// The storage primary's template: an ECC P-256 restricted decryption key
/// with AES-128-CFB, the TCG provisioning guidance's SRK shape, with a
/// 32-byte zero `unique` for each coordinate. Fixed, so a TPM re-derives the
/// same parent from its owner seed on every boot.
pub fn storage_primary_template() -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(&TPM_ALG_ECC.to_be_bytes());
    t.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    t.extend_from_slice(&STORAGE_PRIMARY_ATTRIBUTES.to_be_bytes());
    t.extend_from_slice(&0u16.to_be_bytes()); // authPolicy
    t.extend_from_slice(&TPM_ALG_AES.to_be_bytes());
    t.extend_from_slice(&128u16.to_be_bytes());
    t.extend_from_slice(&TPM_ALG_CFB.to_be_bytes());
    t.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // scheme
    t.extend_from_slice(&TPM_ECC_NIST_P256.to_be_bytes());
    t.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // kdf
    t.extend_from_slice(&32u16.to_be_bytes());
    t.extend_from_slice(&[0u8; 32]);
    t.extend_from_slice(&32u16.to_be_bytes());
    t.extend_from_slice(&[0u8; 32]);
    t
}

/// The federation key's template: ECDSA P-256 / SHA-256, the attributes
/// [`FEDERATION_KEY_ATTRIBUTES`], and `auth_policy`.
fn federation_key_template(auth_policy: &[u8; 32]) -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(&TPM_ALG_ECC.to_be_bytes());
    t.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    t.extend_from_slice(&FEDERATION_KEY_ATTRIBUTES.to_be_bytes());
    t.extend_from_slice(&32u16.to_be_bytes());
    t.extend_from_slice(auth_policy);
    t.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // symmetric
    t.extend_from_slice(&TPM_ALG_ECDSA.to_be_bytes());
    t.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    t.extend_from_slice(&TPM_ECC_NIST_P256.to_be_bytes());
    t.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // kdf
    t.extend_from_slice(&[0, 0, 0, 0]); // unique: empty x, y
    t
}

/// A federation key as the disk holds it: the TPM's wrapping of the private
/// key (`TPM2B_PRIVATE`, encrypted and integrity-protected under the storage
/// primary's seed), the public area (`TPM2B_PUBLIC`), and the PCRs its policy
/// selects. Nothing here is the private scalar; it never leaves the TPM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedKey {
    public: Vec<u8>,
    private: Vec<u8>,
    policy_pcrs: BTreeSet<u8>,
    parsed: EccP256Public,
}

impl WrappedKey {
    /// A wrapped key from its stored parts.
    ///
    /// # Errors
    /// The public area is not a policy-bound P-256 signing key, or the
    /// private part is not a non-empty `TPM2B`.
    pub fn from_parts(
        public: Vec<u8>,
        private: Vec<u8>,
        policy_pcrs: BTreeSet<u8>,
    ) -> Result<Self, AttestError> {
        let parsed = EccP256Public::from_tpm2b_public(&public)?;
        let problems = parsed.federation_key_problems();
        if !problems.is_empty() {
            return Err(AttestError::Other(format!(
                "not a policy-bound TPM signing key: {problems:?}"
            )));
        }
        let mut r = Reader::new(&private, "TPM2B_PRIVATE");
        if r.tpm2b()?.is_empty() {
            return Err(AttestError::Other("TPM2B_PRIVATE is empty".into()));
        }
        r.finish()?;
        pcr_selection_bytes(&policy_pcrs)?;
        Ok(Self {
            public,
            private,
            policy_pcrs,
            parsed,
        })
    }

    /// The `TPM2B_PUBLIC`.
    pub fn public(&self) -> &[u8] {
        &self.public
    }

    /// The `TPM2B_PRIVATE` (TPM-wrapped).
    pub fn private(&self) -> &[u8] {
        &self.private
    }

    /// The PCRs the key's policy selects.
    pub fn policy_pcrs(&self) -> &BTreeSet<u8> {
        &self.policy_pcrs
    }

    /// The public point, `(x, y)`, 32 bytes each.
    pub fn point(&self) -> ([u8; 32], [u8; 32]) {
        (self.parsed.x, self.parsed.y)
    }

    /// Whether the key's policy is satisfied by these PCR values, computed
    /// the way the verifier computes it. Lets a node see that a key belongs
    /// to another boot state without asking the TPM to refuse a signature.
    ///
    /// # Errors
    /// A selected PCR has no value.
    pub fn policy_matches(&self, values: &BTreeMap<u8, [u8; 32]>) -> Result<bool, AttestError> {
        Ok(self.parsed.auth_policy == policy_pcr_digest(&self.policy_pcrs, values)?)
    }
}

impl<T: Transport> Tpm<T> {
    /// The storage primary under the owner hierarchy: its handle and its
    /// `TPM2B_PUBLIC`.
    pub fn storage_primary(&mut self) -> Result<(u32, Vec<u8>), AttestError> {
        self.create_primary_in(TPM_RH_OWNER, &storage_primary_template())
    }

    /// `TPM2_Create` under `parent`. Returns (`TPM2B_PRIVATE`, `TPM2B_PUBLIC`).
    fn create(&mut self, parent: u32, template: &[u8]) -> Result<(Vec<u8>, Vec<u8>), AttestError> {
        let mut params = Vec::new();
        params.extend_from_slice(&[0, 4, 0, 0, 0, 0]); // empty userAuth and data
        tpm2b(&mut params, template)?;
        tpm2b(&mut params, &[])?; // outsideInfo
        params.extend_from_slice(&0u32.to_be_bytes()); // creationPCR: none
        let resp = self.command(CC_CREATE, &[parent], &[Session::Password], 0, &params)?;
        let mut r = Reader::new(&resp.params, "Create response");
        let mut private = Vec::new();
        tpm2b(&mut private, r.tpm2b()?)?;
        let mut public = Vec::new();
        tpm2b(&mut public, r.tpm2b()?)?;
        Ok((private, public))
    }

    /// `TPM2_Load` a wrapped key under `parent`. Fails with
    /// `TPM_RC_INTEGRITY` when the blob was not wrapped by this parent.
    fn load(&mut self, parent: u32, key: &WrappedKey) -> Result<u32, AttestError> {
        let mut params = key.private.clone();
        params.extend_from_slice(&key.public);
        let resp = self.command(CC_LOAD, &[parent], &[Session::Password], 1, &params)?;
        resp.handles
            .first()
            .copied()
            .ok_or_else(|| AttestError::Other("Load returned no handle".into()))
    }

    /// An unbound, unsalted policy session (SHA-256).
    fn start_policy_session(&mut self) -> Result<u32, AttestError> {
        let mut params = Vec::new();
        tpm2b(&mut params, &[0x5a; 16])?; // nonceCaller: no HMAC uses it
        tpm2b(&mut params, &[])?; // encryptedSalt
        params.push(TPM_SE_POLICY);
        params.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // symmetric
        params.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes()); // authHash
        let resp = self.command(
            CC_START_AUTH_SESSION,
            &[TPM_RH_NULL, TPM_RH_NULL],
            &[],
            1,
            &params,
        )?;
        resp.handles
            .first()
            .copied()
            .ok_or_else(|| AttestError::Other("StartAuthSession returned no handle".into()))
    }

    /// `TPM2_PolicyPCR` with an empty `pcrDigest`: the TPM extends the
    /// session's digest with the PCRs' CURRENT values, so a session run in
    /// another boot state reaches another digest.
    fn policy_pcr(&mut self, session: u32, pcrs: &BTreeSet<u8>) -> Result<(), AttestError> {
        let mut params = Vec::new();
        tpm2b(&mut params, &[])?;
        params.extend_from_slice(&pcr_selection_bytes(pcrs)?);
        self.command(CC_POLICY_PCR, &[session], &[], 0, &params)
            .map(|_| ())
    }

    /// `TPM2_Sign` of a SHA-256 digest with the key's own scheme (ECDSA),
    /// authorized by `session`. Returns `r || s`.
    fn sign_digest(
        &mut self,
        key: u32,
        session: u32,
        digest: &[u8; 32],
    ) -> Result<[u8; 64], AttestError> {
        let mut params = Vec::new();
        tpm2b(&mut params, digest)?;
        params.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // inScheme: the key's
        params.extend_from_slice(&TPM_ST_HASHCHECK.to_be_bytes());
        params.extend_from_slice(&TPM_RH_NULL.to_be_bytes());
        tpm2b(&mut params, &[])?; // a NULL ticket: the key is not restricted
        let resp = self.command(CC_SIGN, &[key], &[Session::Policy(session)], 0, &params)?;
        let mut r = Reader::new(&resp.params, "Sign response");
        let alg = r.be_u16()?;
        let hash = r.be_u16()?;
        if (alg, hash) != (TPM_ALG_ECDSA, TPM_ALG_SHA256) {
            return Err(AttestError::Other(format!(
                "Sign returned scheme 0x{alg:04x}/0x{hash:04x}, not ECDSA/SHA-256"
            )));
        }
        let sr = r.tpm2b()?;
        let ss = r.tpm2b()?;
        r.finish()?;
        let mut out = [0u8; 64];
        let (rr, rs) = out.split_at_mut(32);
        pad_into(rr, sr)?;
        pad_into(rs, ss)?;
        Ok(out)
    }

    /// `TPM2_Certify` `object` with `signer` over `qualifying`. Returns
    /// (`TPMS_ATTEST`, `TPMT_SIGNATURE`).
    fn certify(
        &mut self,
        object: u32,
        signer: u32,
        qualifying: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), AttestError> {
        let mut params = Vec::new();
        tpm2b(&mut params, qualifying)?;
        params.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // the signer's scheme
        let resp = self.command(
            CC_CERTIFY,
            &[object, signer],
            &[Session::Password, Session::Password],
            0,
            &params,
        )?;
        let mut r = Reader::new(&resp.params, "Certify response");
        let attest = r.tpm2b()?.to_vec();
        let signature = r.bytes(r.remaining())?.to_vec();
        Ok((attest, signature))
    }

    /// `TPM2_PCR_Extend` the SHA-256 bank of `pcr` with `digest`. For tests
    /// and the live check that a moved boot state stops the key.
    pub fn pcr_extend(&mut self, pcr: u8, digest: &[u8; 32]) -> Result<(), AttestError> {
        let mut params = Vec::new();
        params.extend_from_slice(&1u32.to_be_bytes());
        params.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        params.extend_from_slice(digest);
        self.command(
            CC_PCR_EXTEND,
            &[u32::from(pcr)],
            &[Session::Password],
            0,
            &params,
        )
        .map(|_| ())
    }

    /// Load `key` under the storage primary, flushing the primary.
    fn load_federation_key(&mut self, key: &WrappedKey) -> Result<u32, AttestError> {
        let (parent, _) = self.storage_primary()?;
        let loaded = self.load(parent, key);
        let flushed = self.flush(parent);
        let handle = loaded?;
        if let Err(e) = flushed {
            let _ = self.flush(handle);
            return Err(e);
        }
        Ok(handle)
    }
}

fn pad_into(out: &mut [u8], b: &[u8]) -> Result<(), AttestError> {
    let b = match b.iter().position(|&x| x != 0) {
        Some(i) => b.get(i..).unwrap_or_default(),
        None => &[],
    };
    let start = out
        .len()
        .checked_sub(b.len())
        .ok_or_else(|| AttestError::Other("signature scalar longer than 32 bytes".into()))?;
    out.get_mut(start..)
        .ok_or_else(|| AttestError::Other("signature scalar".into()))?
        .copy_from_slice(b);
    Ok(())
}

/// Create a federation key bound to `pcrs` at their current values.
///
/// The policy digest is computed here, from a `PCR_Read`, by the same
/// function the verifier uses ([`policy_pcr_digest`]); the TPM then checks
/// it independently at every signature, by running `PolicyPCR` itself. A
/// mistake in the computation is a key that never signs, not one that signs
/// unbound.
///
/// # Errors
/// The TPM refused a command, or `pcrs` is empty or above PCR 23.
pub fn create_federation_key<T: Transport>(
    tpm: &mut Tpm<T>,
    pcrs: &BTreeSet<u8>,
) -> Result<WrappedKey, AttestError> {
    let values = tpm.pcr_read(pcrs)?;
    let policy = policy_pcr_digest(pcrs, &values)?;
    let (parent, _) = tpm.storage_primary()?;
    let created = tpm.create(parent, &federation_key_template(&policy));
    let flushed = tpm.flush(parent);
    let (private, public) = created?;
    flushed?;
    WrappedKey::from_parts(public, private, pcrs.clone())
}

/// Sign a SHA-256 digest with a federation key: load it, run `PolicyPCR` in a
/// fresh policy session, `Sign`. Every handle is flushed whatever happens.
///
/// # Errors
/// [`AttestError::is_policy_failure`] when the PCRs are not the key's boot
/// state; [`AttestError::is_integrity_failure`] when the blob is not this
/// TPM's.
pub fn sign_with_federation_key<T: Transport>(
    tpm: &mut Tpm<T>,
    key: &WrappedKey,
    digest: &[u8; 32],
) -> Result<[u8; 64], AttestError> {
    let handle = tpm.load_federation_key(key)?;
    let signed = (|| -> Result<[u8; 64], AttestError> {
        let session = tpm.start_policy_session()?;
        let result = tpm
            .policy_pcr(session, &key.policy_pcrs)
            .and_then(|()| tpm.sign_digest(handle, session, digest));
        // A successful Sign ends the session (continueSession is clear); a
        // failed command leaves it loaded.
        if result.is_err() {
            let _ = tpm.flush(session);
        }
        result
    })();
    let flushed = tpm.flush(handle);
    let sig = signed?;
    flushed?;
    Ok(sig)
}

impl<T: Transport> Attester<T> {
    /// Certify `key` with this attester's AK: `TPM2_Certify` over
    /// [`certify_qualifying_data`], published as a custody statement.
    ///
    /// # Errors
    /// The TPM refused a command (including `Load`, if the blob is not this
    /// TPM's).
    pub fn certify_federation_key(
        &mut self,
        key: &WrappedKey,
    ) -> Result<CustodyStatement, AttestError> {
        let (parent, parent_public) = self.tpm.storage_primary()?;
        let loaded = self.tpm.load(parent, key);
        let flushed = self.tpm.flush(parent);
        let handle = loaded?;
        flushed?;
        let certified = (|| -> Result<(Vec<u8>, Vec<u8>), AttestError> {
            let template = self.template.template(&mut self.tpm)?;
            let (ak, _) = self.tpm.create_primary(&template)?;
            let result = self.tpm.certify(handle, ak, &certify_qualifying_data());
            let flushed = self.tpm.flush(ak);
            let out = result?;
            flushed?;
            Ok(out)
        })();
        let flushed = self.tpm.flush(handle);
        let (attest, signature) = certified?;
        flushed?;
        Ok(CustodyStatement::Tpm(TpmCustodyStatement {
            public: b64(&key.public),
            parent_public: b64(&parent_public),
            policy_pcrs: key.policy_pcrs.clone(),
            certify_attest: b64(&attest),
            certify_signature: b64(&signature),
        }))
    }
}

fn b64(b: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// Where a TPM is: the kernel's device, or a software TPM's socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TpmEndpoint {
    /// A character device, `/dev/tpmrm0` in production.
    Device(PathBuf),
    /// A software TPM's raw data socket (`host:port`). Tests and development
    /// only: nothing authenticates the peer.
    Socket(String),
}

impl TpmEndpoint {
    /// Open a connection.
    ///
    /// # Errors
    /// The device cannot be opened or the socket cannot be reached.
    pub fn connect(&self) -> Result<Tpm<AnyTransport>, AttestError> {
        Ok(Tpm::new(match self {
            Self::Device(p) => AnyTransport::Device(DeviceTransport::open(p)?),
            Self::Socket(a) => AnyTransport::Socket(SocketTransport::connect(a)?),
        }))
    }
}

impl std::fmt::Display for TpmEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Device(p) => write!(f, "{}", p.display()),
            Self::Socket(a) => write!(f, "swtpm socket {a}"),
        }
    }
}

/// Either transport, so one signer type serves both.
pub enum AnyTransport {
    /// [`DeviceTransport`].
    Device(DeviceTransport),
    /// [`SocketTransport`].
    Socket(SocketTransport),
}

impl Transport for AnyTransport {
    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, AttestError> {
        match self {
            Self::Device(d) => d.transmit(command),
            Self::Socket(s) => s.transmit(command),
        }
    }
}
