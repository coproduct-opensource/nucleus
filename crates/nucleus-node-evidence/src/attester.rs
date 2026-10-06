//! The Attester role (RFC 9334): ask a TPM 2.0 for a quote bound to the
//! node's keys, and assemble the evidence document.
//!
//! Raw TPM 2.0 commands over a byte transport — the kernel's resource-managed
//! device (`/dev/tpmrm0`) in production, a software TPM's socket in tests. No
//! `libtss2`: the six commands this needs (`NV_ReadPublic`, `NV_Read`,
//! `CreatePrimary`, `PCR_Read`, `Quote`, `FlushContext`) with password sessions
//! are a few hundred lines of marshalling, and the result links statically
//! into a musl node binary with no C dependency. The output is checked by the
//! same verifier a relying party runs ([`crate::appraise`]), and the verifier
//! is tested against quotes from an independent stack, so this marshalling is
//! never its own oracle.
//!
//! The attester checks its own work before publishing: the PCR values it read
//! must hash to the digest the TPM quoted. PCR 10 moves whenever IMA measures
//! a file, so a read that raced a measurement is retried, never published.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::anchor::AkAnchorClaim;
use crate::binding::{Freshness, KeyBinding, qualifying_data};
use crate::crypto::sha256;
use crate::evidence::{BootLog, EVIDENCE_PROFILE, ImaLog, NodeEvidence, TpmQuote};
use crate::ima::ImaLogFormat;
use crate::wire::Reader;

const TPM_ST_NO_SESSIONS: u16 = 0x8001;
const TPM_ST_SESSIONS: u16 = 0x8002;
const TPM_RH_OWNER: u32 = 0x4000_0001;
const TPM_RH_ENDORSEMENT: u32 = 0x4000_000B;
const TPM_ALG_SHA256: u16 = 0x000B;
const TPM_ALG_NULL: u16 = 0x0010;
const TPM_ALG_ECDSA: u16 = 0x0018;
const TPM_ALG_ECC: u16 = 0x0023;
const TPM_ECC_NIST_P256: u16 = 0x0003;

const TPM_RC_YIELDED: u32 = 0x0000_0908;
const TPM_RC_TESTING: u32 = 0x0000_090A;
const TPM_RC_RETRY: u32 = 0x0000_0922;

const CC_NV_READ: u32 = 0x0000_014E;
const CC_CREATE_PRIMARY: u32 = 0x0000_0131;
const CC_QUOTE: u32 = 0x0000_0158;
const CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
const CC_NV_READ_PUBLIC: u32 = 0x0000_0169;
const CC_PCR_READ: u32 = 0x0000_017E;

/// The largest response this attester accepts from a TPM.
const MAX_RESPONSE: usize = 8192;
/// How many times a quote is retaken when PCRs moved under it.
const QUOTE_ATTEMPTS: usize = 5;

/// Why attestation failed.
#[derive(Debug, thiserror::Error)]
pub enum AttestError {
    /// The transport failed.
    #[error("TPM transport: {0}")]
    Io(#[from] std::io::Error),
    /// The TPM returned an error code.
    #[error("TPM command 0x{command:x} failed with response code 0x{code:x}")]
    Tpm {
        /// The command code.
        command: u32,
        /// The TPM response code.
        code: u32,
    },
    /// A response did not parse.
    #[error("TPM response: {0}")]
    Malformed(#[from] crate::Malformed),
    /// The PCRs kept moving between read and quote.
    #[error("PCR values changed during every one of {0} quote attempts")]
    PcrsKeptMoving(usize),
    /// Anything else.
    #[error("{0}")]
    Other(String),
}

/// A byte pipe to a TPM: one command in, one response out.
pub trait Transport {
    /// Send `command`, return the complete response.
    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, AttestError>;
}

/// Read one TPM response (header `tag u16, size u32, ...`) from a stream.
fn read_response(r: &mut impl Read) -> Result<Vec<u8>, AttestError> {
    let mut header = [0u8; 10];
    r.read_exact(&mut header)?;
    let size = u32::from_be_bytes([header[2], header[3], header[4], header[5]]);
    let size = usize::try_from(size).map_err(|_| AttestError::Other("size".into()))?;
    if !(10..=MAX_RESPONSE).contains(&size) {
        return Err(AttestError::Other(format!("TPM response size {size}")));
    }
    let mut out = header.to_vec();
    out.resize(size, 0);
    r.read_exact(out.get_mut(10..).unwrap_or_default())?;
    Ok(out)
}

/// The kernel's TPM character device. Prefer the resource-managed
/// `/dev/tpmrm0`: it flushes this process's transient objects if it dies.
pub struct DeviceTransport {
    file: std::fs::File,
}

impl DeviceTransport {
    /// Open the device read-write.
    pub fn open(path: &Path) -> Result<Self, AttestError> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;
        Ok(Self { file })
    }
}

impl Transport for DeviceTransport {
    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, AttestError> {
        self.file.write_all(command)?;
        // The device returns the whole response to one read.
        let mut buf = vec![0u8; MAX_RESPONSE];
        let n = self.file.read(&mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }
}

/// A software TPM's raw data socket (swtpm `--server type=tcp`), for tests
/// and development. Not for production: nothing authenticates the peer.
pub struct SocketTransport {
    stream: std::net::TcpStream,
}

impl SocketTransport {
    /// Connect to `addr`.
    pub fn connect(addr: &str) -> Result<Self, AttestError> {
        Ok(Self {
            stream: std::net::TcpStream::connect(addr)?,
        })
    }
}

impl Transport for SocketTransport {
    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, AttestError> {
        self.stream.write_all(command)?;
        read_response(&mut self.stream)
    }
}

fn tpm2b(out: &mut Vec<u8>, b: &[u8]) -> Result<(), AttestError> {
    let n = u16::try_from(b.len()).map_err(|_| AttestError::Other("TPM2B too long".into()))?;
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(b);
    Ok(())
}

fn pcr_selection(out: &mut Vec<u8>, pcrs: &BTreeSet<u8>) {
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    let mut bits = [0u8; 3];
    for p in pcrs {
        if let Some(b) = bits.get_mut(usize::from(p / 8)) {
            *b |= 1 << (p % 8);
        }
    }
    out.push(3);
    out.extend_from_slice(&bits);
}

/// An empty-password session on one handle.
const PASSWORD_SESSION: [u8; 13] = [
    0, 0, 0, 9, // authorizationSize
    0x40, 0, 0, 9, // TPM_RS_PW
    0, 0, // nonce
    1, // continueSession
    0, 0, // hmac (empty password)
];

/// A TPM, through a transport.
pub struct Tpm<T: Transport> {
    transport: T,
}

/// One command's response, past the header.
struct Response {
    handles: Vec<u32>,
    params: Vec<u8>,
}

impl<T: Transport> Tpm<T> {
    /// Wrap a transport.
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    fn command(
        &mut self,
        code: u32,
        handles: &[u32],
        authorized: bool,
        response_handles: usize,
        params: &[u8],
    ) -> Result<Response, AttestError> {
        let mut body = Vec::new();
        for h in handles {
            body.extend_from_slice(&h.to_be_bytes());
        }
        if authorized {
            body.extend_from_slice(&PASSWORD_SESSION);
        }
        body.extend_from_slice(params);
        let tag = if authorized {
            TPM_ST_SESSIONS
        } else {
            TPM_ST_NO_SESSIONS
        };
        let size = u32::try_from(body.len().saturating_add(10))
            .map_err(|_| AttestError::Other("command too long".into()))?;
        let mut cmd = Vec::with_capacity(body.len().saturating_add(10));
        cmd.extend_from_slice(&tag.to_be_bytes());
        cmd.extend_from_slice(&size.to_be_bytes());
        cmd.extend_from_slice(&code.to_be_bytes());
        cmd.extend_from_slice(&body);
        // TPM_RC_RETRY, TPM_RC_YIELDED and TPM_RC_TESTING ask the caller to
        // send the same command again; anything else nonzero is a failure.
        let mut attempts = 0usize;
        let resp = loop {
            let resp = self.transport.transmit(&cmd)?;
            let rc = resp
                .get(6..10)
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
                .map(u32::from_be_bytes);
            attempts = attempts.saturating_add(1);
            match rc {
                Some(TPM_RC_RETRY | TPM_RC_YIELDED | TPM_RC_TESTING) if attempts < 20 => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                _ => break resp,
            }
        };
        let mut r = Reader::new(&resp, "TPM response");
        let rtag = r.be_u16()?;
        let _size = r.be_u32()?;
        let rc = r.be_u32()?;
        if rc != 0 {
            return Err(AttestError::Tpm {
                command: code,
                code: rc,
            });
        }
        let mut out_handles = Vec::new();
        for _ in 0..response_handles {
            out_handles.push(r.be_u32()?);
        }
        let params = if rtag == TPM_ST_SESSIONS {
            let n = usize::try_from(r.be_u32()?).map_err(|_| AttestError::Other("size".into()))?;
            r.bytes(n)?.to_vec()
        } else {
            r.bytes(r.remaining())?.to_vec()
        };
        Ok(Response {
            handles: out_handles,
            params,
        })
    }

    /// Read a whole NV index (owner authorization, empty password).
    pub fn nv_read(&mut self, index: u32) -> Result<Vec<u8>, AttestError> {
        let public = self.command(CC_NV_READ_PUBLIC, &[index], false, 0, &[])?;
        let mut r = Reader::new(&public.params, "TPM2B_NV_PUBLIC");
        let nv_public = r.tpm2b()?;
        let mut p = Reader::new(nv_public, "TPMS_NV_PUBLIC");
        let _index = p.be_u32()?;
        let _name_alg = p.be_u16()?;
        let _attrs = p.be_u32()?;
        let _policy = p.tpm2b()?;
        let size = p.be_u16()?;
        let mut data = Vec::new();
        while data.len() < usize::from(size) {
            let offset = u16::try_from(data.len()).unwrap_or(u16::MAX);
            let chunk = size.saturating_sub(offset).min(512);
            let mut params = Vec::new();
            params.extend_from_slice(&chunk.to_be_bytes());
            params.extend_from_slice(&offset.to_be_bytes());
            let resp = self.command(CC_NV_READ, &[TPM_RH_OWNER, index], true, 0, &params)?;
            let mut r = Reader::new(&resp.params, "TPM2B_MAX_NV_BUFFER");
            let got = r.tpm2b()?;
            if got.is_empty() {
                return Err(AttestError::Other("NV_Read returned no data".into()));
            }
            data.extend_from_slice(got);
        }
        Ok(data)
    }

    /// Create a primary key under the endorsement hierarchy from a
    /// `TPMT_PUBLIC` template. Returns its handle and `TPM2B_PUBLIC`.
    pub fn create_primary(&mut self, template: &[u8]) -> Result<(u32, Vec<u8>), AttestError> {
        let mut params = Vec::new();
        // TPM2B_SENSITIVE_CREATE { userAuth: empty, data: empty }
        params.extend_from_slice(&[0, 4, 0, 0, 0, 0]);
        tpm2b(&mut params, template)?;
        tpm2b(&mut params, &[])?; // outsideInfo
        params.extend_from_slice(&0u32.to_be_bytes()); // creationPCR: none
        let resp = self.command(CC_CREATE_PRIMARY, &[TPM_RH_ENDORSEMENT], true, 1, &params)?;
        let handle = *resp
            .handles
            .first()
            .ok_or_else(|| AttestError::Other("CreatePrimary returned no handle".into()))?;
        let mut r = Reader::new(&resp.params, "CreatePrimary response");
        let public = r.tpm2b()?;
        let mut out = Vec::new();
        tpm2b(&mut out, public)?;
        Ok((handle, out))
    }

    /// Read SHA-256 PCR values. The TPM returns at most eight per call.
    pub fn pcr_read(&mut self, pcrs: &BTreeSet<u8>) -> Result<BTreeMap<u8, [u8; 32]>, AttestError> {
        let mut out = BTreeMap::new();
        let mut want = pcrs.clone();
        while !want.is_empty() {
            let mut params = Vec::new();
            pcr_selection(&mut params, &want);
            let resp = self.command(CC_PCR_READ, &[], false, 0, &params)?;
            let mut r = Reader::new(&resp.params, "PCR_Read response");
            let _update_counter = r.be_u32()?;
            let banks = r.be_u32()?;
            let mut returned = Vec::new();
            for _ in 0..banks {
                let _alg = r.be_u16()?;
                let n = r.u8()?;
                let bits = r.bytes(usize::from(n))?;
                for (byte_index, byte) in bits.iter().enumerate() {
                    for bit in 0..8u8 {
                        if byte & (1 << bit) != 0 {
                            let i = byte_index
                                .checked_mul(8)
                                .and_then(|b| u8::try_from(b).ok())
                                .and_then(|b| b.checked_add(bit))
                                .ok_or_else(|| AttestError::Other("PCR index".into()))?;
                            returned.push(i);
                        }
                    }
                }
            }
            let count = r.be_u32()?;
            if count == 0 || usize::try_from(count).ok() != Some(returned.len()) {
                return Err(AttestError::Other(format!(
                    "PCR_Read returned {count} digests for {} PCRs",
                    returned.len()
                )));
            }
            for i in returned {
                let d = r.tpm2b()?;
                let d: [u8; 32] = d
                    .try_into()
                    .map_err(|_| AttestError::Other("PCR digest is not 32 bytes".into()))?;
                out.insert(i, d);
                want.remove(&i);
            }
        }
        Ok(out)
    }

    /// Quote `pcrs` over `qualifying` with the key at `handle`, using the
    /// key's own signing scheme. Returns (`TPMS_ATTEST`, `TPMT_SIGNATURE`).
    pub fn quote(
        &mut self,
        handle: u32,
        qualifying: &[u8],
        pcrs: &BTreeSet<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), AttestError> {
        let mut params = Vec::new();
        tpm2b(&mut params, qualifying)?;
        params.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        pcr_selection(&mut params, pcrs);
        let resp = self.command(CC_QUOTE, &[handle], true, 0, &params)?;
        let mut r = Reader::new(&resp.params, "Quote response");
        let attest = r.tpm2b()?.to_vec();
        let signature = r.bytes(r.remaining())?.to_vec();
        Ok((attest, signature))
    }

    /// Flush a transient object.
    pub fn flush(&mut self, handle: u32) -> Result<(), AttestError> {
        self.command(CC_FLUSH_CONTEXT, &[], false, 0, &handle.to_be_bytes())
            .map(|_| ())
    }
}

/// Where the attestation key's template comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AkTemplate {
    /// A `TPMT_PUBLIC` template stored in an NV index — how a cloud
    /// provider publishes the template of the AK its API vouches for.
    NvIndex(u32),
    /// A standard ECC P-256 restricted signing key (ECDSA/SHA-256), the
    /// shape `tpm2_createak` makes. Anchored only if an operator pins it.
    DefaultEccP256,
}

impl AkTemplate {
    fn template<T: Transport>(&self, tpm: &mut Tpm<T>) -> Result<Vec<u8>, AttestError> {
        match self {
            Self::NvIndex(i) => tpm.nv_read(*i),
            Self::DefaultEccP256 => {
                let mut t = Vec::new();
                t.extend_from_slice(&TPM_ALG_ECC.to_be_bytes());
                t.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
                // fixedTPM|fixedParent|sensitiveDataOrigin|userWithAuth|restricted|sign
                t.extend_from_slice(&0x0005_0072u32.to_be_bytes());
                t.extend_from_slice(&0u16.to_be_bytes()); // authPolicy
                t.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // symmetric
                t.extend_from_slice(&TPM_ALG_ECDSA.to_be_bytes());
                t.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
                t.extend_from_slice(&TPM_ECC_NIST_P256.to_be_bytes());
                t.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // kdf
                t.extend_from_slice(&[0, 0, 0, 0]); // unique: empty x, y
                Ok(t)
            }
        }
    }
}

/// Where the logs are read from. Each is optional on the machine, and an
/// absent log is recorded as absent with this reason, never omitted.
#[derive(Clone, Debug)]
pub struct LogSources {
    /// The firmware event log (`/sys/kernel/security/tpm0/binary_bios_measurements`).
    pub boot_event_log: PathBuf,
    /// The IMA per-bank SHA-256 list, preferred when present.
    pub ima_sha256: PathBuf,
    /// The IMA list with SHA-1 template digests, the fallback.
    pub ima_sha1: PathBuf,
}

impl LogSources {
    /// The Linux securityfs paths.
    pub fn linux() -> Self {
        Self {
            boot_event_log: "/sys/kernel/security/tpm0/binary_bios_measurements".into(),
            ima_sha256: "/sys/kernel/security/ima/binary_runtime_measurements_sha256".into(),
            ima_sha1: "/sys/kernel/security/ima/binary_runtime_measurements".into(),
        }
    }

    fn boot(&self) -> BootLog {
        match std::fs::read(&self.boot_event_log) {
            Ok(b) => BootLog::attach(&b),
            Err(e) => BootLog::Absent(format!("{}: {e}", self.boot_event_log.display())),
        }
    }

    fn ima(&self) -> ImaLog {
        match std::fs::read(&self.ima_sha256) {
            Ok(b) => ImaLog::attach(ImaLogFormat::Sha256TemplateDigests, &b),
            Err(_) => match std::fs::read(&self.ima_sha1) {
                Ok(b) => ImaLog::attach(ImaLogFormat::Sha1TemplateDigests, &b),
                Err(e) => ImaLog::Absent(format!("{}: {e}", self.ima_sha1.display())),
            },
        }
    }
}

/// The PCRs quoted by default: the boot chain (0-9), IMA (10), and shim's
/// MOK state (14).
pub fn default_pcrs() -> BTreeSet<u8> {
    (0..=10).chain([14]).collect()
}

/// An attester: a TPM, an AK template, the PCRs to quote, the logs, and the
/// anchor the node claims for its AK.
pub struct Attester<T: Transport> {
    tpm: Tpm<T>,
    template: AkTemplate,
    pcrs: BTreeSet<u8>,
    logs: LogSources,
    anchor: AkAnchorClaim,
}

impl<T: Transport> Attester<T> {
    /// Assemble an attester.
    pub fn new(
        tpm: Tpm<T>,
        template: AkTemplate,
        pcrs: BTreeSet<u8>,
        logs: LogSources,
        anchor: AkAnchorClaim,
    ) -> Self {
        Self {
            tpm,
            template,
            pcrs,
            logs,
            anchor,
        }
    }

    /// The AK's `TPM2B_PUBLIC`, for an operator to fingerprint and pin.
    pub fn ak_public(&mut self) -> Result<Vec<u8>, AttestError> {
        let template = self.template.template(&mut self.tpm)?;
        let (handle, public) = self.tpm.create_primary(&template)?;
        self.tpm.flush(handle)?;
        Ok(public)
    }

    /// Quote over `binding` + `freshness` and assemble the evidence. The
    /// logs are read after the quote: the boot log is fixed by then, and the
    /// IMA log only grows, which the verifier's prefix replay accepts.
    pub fn attest(
        &mut self,
        binding: &KeyBinding,
        freshness: Freshness,
    ) -> Result<NodeEvidence, AttestError> {
        let template = self.template.template(&mut self.tpm)?;
        let (handle, ak_public) = self.tpm.create_primary(&template)?;
        let result = self.quote_consistently(handle, &qualifying_data(binding, &freshness));
        let flushed = self.tpm.flush(handle);
        let (attest, signature, pcrs) = result?;
        flushed?;
        Ok(NodeEvidence {
            eat_profile: EVIDENCE_PROFILE.into(),
            binding: binding.clone(),
            freshness,
            tpm: TpmQuote::from_parts(&ak_public, &attest, &signature, &pcrs),
            boot_event_log: self.logs.boot(),
            ima_log: self.logs.ima(),
            ak_anchor: self.anchor.clone(),
        })
    }

    fn quote_consistently(
        &mut self,
        handle: u32,
        qualifying: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, BTreeMap<u8, [u8; 32]>), AttestError> {
        for _ in 0..QUOTE_ATTEMPTS {
            let (attest, signature) = self.tpm.quote(handle, qualifying, &self.pcrs)?;
            let pcrs = self.tpm.pcr_read(&self.pcrs)?;
            let quoted = crate::tpm::parse_quote(&attest)?;
            let concat: Vec<u8> = pcrs.values().flatten().copied().collect();
            if quoted.pcr_digest == sha256(&concat) {
                return Ok((attest, signature, pcrs));
            }
        }
        Err(AttestError::PcrsKeptMoving(QUOTE_ATTEMPTS))
    }
}
