//! TLS termination (ADR 0015 §4, step E3), built to `TlsTermination.lean`.
//!
//! The pod's CA arrives once, at start ([`PodCa::from_bundle`]). The proxy
//! terminates a guest's `CONNECT host:port` with a leaf it mints for the TLS
//! name, reads each request in clear, and only then asks the node to decide
//! it. Every handshake ends in one [`TlsVerdict`], computed by the kernel's
//! extracted [`tls_verdict`] (proved equal to `TlsTermination.step` in
//! `TlsTerminationExtracted.lean`); this module restates none of its
//! conditions.
//!
//! # One source for each fact
//!
//! The names the pod may reach and the CA's deadline are read from the CA
//! certificate itself (its `nameConstraints` permitted DNS subtrees and its
//! `notAfter`), not passed beside it, so the certificate the guest trusts and
//! the proxy's decision cannot disagree (ADR 0007 G-1). The proxy mints a leaf
//! only for a name that is exactly one of those subtrees (the model's
//! `permitted.contains`); the X.509 constraint, which also admits subdomains,
//! stays the client's ceiling, never the proxy's grant.
//!
//! # How the key arrives
//!
//! `--tls-ca-channel`: the node writes the bundle as the first bytes on its end
//! of the decision channel, before the first `Decide`, and the proxy reads
//! exactly one bundle ([`read_bundle`]) before it serves. An inherited
//! descriptor cannot carry it: the confinement hook marks every descriptor
//! from 3 up close-on-exec (`nucleus::hardening`, found by E3's node side).
//! The key is never in argv, the environment, a file or the guest (ADR 0015
//! §4: the CA key goes only to that pod's proxy).
//!
//! # Which names a leaf is minted for
//!
//! [`Termination`] carries one predicate, [`NamePermit`], that both the leaf
//! minter and the verdict consult. Egress mode: exactly one of the CA's
//! permitted names. Link mode (ADR 0017): `<uuid>.link.nucleus.invalid` for a
//! destination the node has announced a live `LINK` to
//! (`crate::link::Links::permits`), under a CA whose constraints include the
//! link namespace.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use nucleus_ifc_kernel::extracted::tls::{TlsVerdict, may_issue_leaf, tls_verdict};
use rcgen::{CertificateParams, IsCa, Issuer, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::RootCertStore;
use rustls::crypto::ring;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert, ServerConfig};
use rustls::sign::CertifiedKey;
use x509_parser::extensions::GeneralName;

/// The bundle's first line, so a wrong descriptor is refused by name.
const BUNDLE_MAGIC: &[u8] = b"nucleus-pod-ca/1\n";

/// The largest bundle read from the descriptor.
pub const MAX_BUNDLE: usize = 64 * 1024;

/// The ALPN protocol the guest is offered: HTTP/1.1 only (ADR 0015 §4), so the
/// guest-facing parser is HTTP/1.1 alone.
pub const ALPN_HTTP11: &[u8] = b"http/1.1";

/// Why a bundle is not a CA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaError {
    Bundle,
    Certificate,
    NoNameConstraints,
    Key,
}

impl fmt::Display for CaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CaError::Bundle => "not a nucleus-pod-ca/1 bundle",
            CaError::Certificate => "the CA certificate does not parse",
            CaError::NoNameConstraints => {
                "the CA has no permitted DNS name constraints: it would vouch for any name"
            }
            CaError::Key => "the CA key does not parse as PKCS#8 P-256",
        })
    }
}

/// One pod's CA, as its proxy holds it.
pub struct PodCa {
    cert_der: CertificateDer<'static>,
    key_der: Vec<u8>,
    permitted: Vec<String>,
    not_after: u64,
}

impl fmt::Debug for PodCa {
    // The key is never printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PodCa")
            .field("permitted", &self.permitted)
            .field("not_after", &self.not_after)
            .finish_non_exhaustive()
    }
}

fn take<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
    let (len, tail) = rest.split_first_chunk::<4>()?;
    let len = usize::try_from(u32::from_be_bytes(*len)).ok()?;
    if tail.len() < len {
        return None;
    }
    let (field, tail) = tail.split_at(len);
    *rest = tail;
    Some(field)
}

impl PodCa {
    /// `magic | u32 len | CA cert DER | u32 len | CA key PKCS#8 DER`.
    ///
    /// # Errors
    /// [`CaError`] for a malformed bundle, a certificate without permitted DNS
    /// name constraints, or a key that is not P-256 PKCS#8.
    pub fn from_bundle(bytes: &[u8]) -> Result<PodCa, CaError> {
        let mut rest = bytes.strip_prefix(BUNDLE_MAGIC).ok_or(CaError::Bundle)?;
        let cert = take(&mut rest).ok_or(CaError::Bundle)?;
        let key = take(&mut rest).ok_or(CaError::Bundle)?;
        if !rest.is_empty() {
            return Err(CaError::Bundle);
        }
        PodCa::new(cert.to_vec(), key.to_vec())
    }

    /// The bundle for `cert_der` and `key_der` (the node's half; tests).
    #[must_use]
    pub fn to_bundle(cert_der: &[u8], key_der: &[u8]) -> Vec<u8> {
        let mut out = BUNDLE_MAGIC.to_vec();
        for field in [cert_der, key_der] {
            let len = u32::try_from(field.len()).unwrap_or(u32::MAX);
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(field);
        }
        out
    }

    fn new(cert_der: Vec<u8>, key_der: Vec<u8>) -> Result<PodCa, CaError> {
        let (_, cert) =
            x509_parser::parse_x509_certificate(&cert_der).map_err(|_| CaError::Certificate)?;
        let not_after = u64::try_from(cert.validity().not_after.timestamp()).unwrap_or(0);
        let constraints = cert
            .name_constraints()
            .map_err(|_| CaError::Certificate)?
            .ok_or(CaError::NoNameConstraints)?;
        let permitted: Vec<String> = constraints
            .value
            .permitted_subtrees
            .iter()
            .flatten()
            .filter_map(|s| match s.base {
                GeneralName::DNSName(n) => Some(n.to_ascii_lowercase()),
                _ => None,
            })
            .collect();
        if permitted.is_empty() {
            return Err(CaError::NoNameConstraints);
        }
        KeyPair::try_from(key_der.as_slice()).map_err(|_| CaError::Key)?;
        Ok(PodCa {
            cert_der: CertificateDer::from(cert_der),
            key_der,
            permitted,
            not_after,
        })
    }

    /// The names a leaf may be minted for, from the CA's own constraints.
    #[must_use]
    pub fn permitted(&self) -> &[String] {
        &self.permitted
    }

    /// The CA's deadline, unix seconds.
    #[must_use]
    pub fn not_after(&self) -> u64 {
        self.not_after
    }

    /// Whether `name` is exactly one of the permitted names.
    #[must_use]
    pub fn name_permitted(&self, name: &str) -> bool {
        let name = name.to_ascii_lowercase();
        self.permitted.contains(&name)
    }

    /// Whether the CA's constraints include `subtree` (for a link proxy: the
    /// link namespace, so a minted link leaf stays inside what the guest's
    /// trust store accepts).
    #[must_use]
    pub fn permits_subtree(&self, subtree: &str) -> bool {
        self.name_permitted(subtree)
    }
}

/// Read one bundle from the head of the decision channel: the magic, then the
/// two length-prefixed fields, never more than [`MAX_BUNDLE`] bytes in all,
/// and not one byte past the bundle (what follows belongs to the decision
/// protocol). The format is self-delimiting, so nothing else is needed.
///
/// # Errors
/// [`CaError::Bundle`] for a short read, a wrong magic, or a bundle over the
/// bound.
pub fn read_bundle<R: std::io::Read>(channel: &mut R) -> Result<Vec<u8>, CaError> {
    let mut out = vec![0u8; BUNDLE_MAGIC.len()];
    channel.read_exact(&mut out).map_err(|_| CaError::Bundle)?;
    if out != BUNDLE_MAGIC {
        return Err(CaError::Bundle);
    }
    for _field in 0..2 {
        let mut len = [0u8; 4];
        channel.read_exact(&mut len).map_err(|_| CaError::Bundle)?;
        let n = usize::try_from(u32::from_be_bytes(len)).map_err(|_| CaError::Bundle)?;
        let total = out
            .len()
            .checked_add(4)
            .and_then(|t| t.checked_add(n))
            .filter(|t| *t <= MAX_BUNDLE)
            .ok_or(CaError::Bundle)?;
        out.extend_from_slice(&len);
        let start = out.len();
        out.resize(total, 0);
        let field = out.get_mut(start..).ok_or(CaError::Bundle)?;
        channel.read_exact(field).map_err(|_| CaError::Bundle)?;
    }
    Ok(out)
}

/// Which TLS names this proxy mints leaves for and decides: one predicate that
/// the minter and the verdict both consult, so they cannot disagree.
pub type NamePermit = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// Mints a leaf per TLS name on first use, signed by the pod's CA, and caches
/// it. Decides only through [`may_issue_leaf`].
pub struct LeafMinter {
    ca: Arc<PodCa>,
    clock: fn() -> u64,
    permits: NamePermit,
    cache: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

impl fmt::Debug for LeafMinter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LeafMinter")
            .field("ca", &self.ca)
            .finish_non_exhaustive()
    }
}

/// Seconds since the epoch, for the CA's deadline.
///
/// Kept below `LeafMinter` on purpose: `xtask life` attributes a `#[must_use]` to a
/// `pub struct` a few lines after it, and placed above the struct this function's
/// attribute counted `LeafMinter` (a cache, not a one-shot right) as an affine right.
#[must_use]
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl LeafMinter {
    #[must_use]
    pub fn new(ca: Arc<PodCa>, clock: fn() -> u64, permits: NamePermit) -> LeafMinter {
        LeafMinter {
            ca,
            clock,
            permits,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// How many distinct leaves have been minted.
    #[must_use]
    pub fn minted(&self) -> usize {
        self.cache.lock().map_or(0, |c| c.len())
    }

    fn mint(&self, name: &str) -> Option<Arc<CertifiedKey>> {
        let ca_key = KeyPair::try_from(self.ca.key_der.as_slice()).ok()?;
        let issuer = Issuer::from_ca_cert_der(&self.ca.cert_der, ca_key).ok()?;
        let mut params = CertificateParams::new(vec![name.to_string()]).ok()?;
        params.is_ca = IsCa::NoCa;
        let deadline = i64::try_from(self.ca.not_after).ok()?;
        params.not_after = time::OffsetDateTime::from_unix_timestamp(deadline).ok()?;
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).ok()?;
        let leaf = params.signed_by(&leaf_key, &issuer).ok()?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let signer = ring::sign::any_ecdsa_type(&key).ok()?;
        Some(Arc::new(CertifiedKey::new(
            vec![leaf.der().clone()],
            signer,
        )))
    }
}

impl ResolvesServerCert for LeafMinter {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = client_hello.server_name()?.to_ascii_lowercase();
        if !may_issue_leaf(
            true,
            (self.clock)(),
            self.ca.not_after,
            (self.permits)(&name),
        ) {
            return None;
        }
        let mut cache = self.cache.lock().ok()?;
        if let Some(found) = cache.get(&name) {
            return Some(Arc::clone(found));
        }
        let minted = self.mint(&name)?;
        cache.insert(name, Arc::clone(&minted));
        Some(minted)
    }
}

/// What a proxy with TLS termination holds: the CA, the server config built
/// on the minter, and the roots it trusts upstream.
pub struct Termination {
    pub ca: Arc<PodCa>,
    pub minter: Arc<LeafMinter>,
    pub server: Arc<ServerConfig>,
    pub upstream: Arc<rustls::ClientConfig>,
    pub clock: fn() -> u64,
    permits: NamePermit,
}

impl Termination {
    /// Termination for `ca` in egress mode: a leaf only for exactly one of the
    /// CA's permitted names. Upstreams are verified against `upstream_roots`
    /// (the webpki roots in production, [`Termination::webpki`]).
    ///
    /// # Errors
    /// A rustls configuration error, as text.
    pub fn new(
        ca: PodCa,
        upstream_roots: RootCertStore,
        clock: fn() -> u64,
    ) -> Result<Termination, String> {
        let ca = Arc::new(ca);
        let exact = Arc::clone(&ca);
        let permits: NamePermit = Arc::new(move |name: &str| exact.name_permitted(name));
        Termination::with_names(ca, upstream_roots, clock, permits)
    }

    /// Termination for `ca` whose leaves and verdicts admit exactly the names
    /// `permits` admits (link mode: `crate::link::Links::permits`).
    ///
    /// # Errors
    /// A rustls configuration error, as text.
    pub fn with_names(
        ca: Arc<PodCa>,
        upstream_roots: RootCertStore,
        clock: fn() -> u64,
        permits: NamePermit,
    ) -> Result<Termination, String> {
        let minter = Arc::new(LeafMinter::new(
            Arc::clone(&ca),
            clock,
            Arc::clone(&permits),
        ));
        let provider = Arc::new(ring::default_provider());
        let mut server = ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_no_client_auth()
            .with_cert_resolver(Arc::clone(&minter) as Arc<dyn ResolvesServerCert>);
        server.alpn_protocols = vec![ALPN_HTTP11.to_vec()];
        let mut upstream = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_root_certificates(upstream_roots)
            .with_no_client_auth();
        upstream.alpn_protocols = vec![ALPN_HTTP11.to_vec()];
        Ok(Termination {
            ca,
            minter,
            server: Arc::new(server),
            upstream: Arc::new(upstream),
            clock,
            permits,
        })
    }

    /// The verdict for a handshake for `sni` at `now`, before and after the
    /// client's answer and the request's `Host`: the kernel's extracted
    /// [`tls_verdict`], with this proxy's one name predicate.
    #[must_use]
    pub fn verdict(
        &self,
        now: u64,
        sni: Option<&str>,
        accepted: bool,
        sni_matches_host: bool,
    ) -> TlsVerdict {
        let permitted = sni.is_some_and(|n| (self.permits)(&n.to_ascii_lowercase()));
        tls_verdict(
            true,
            now,
            self.ca.not_after,
            permitted,
            accepted,
            sni_matches_host,
        )
    }

    /// The webpki roots, for production.
    #[must_use]
    pub fn webpki() -> RootCertStore {
        RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        }
    }
}

#[cfg(test)]
pub(crate) mod test_ca {
    use super::*;
    use rcgen::{GeneralSubtree, NameConstraints};

    /// A pod CA permitting exactly `names`, valid until `not_after`.
    pub fn mint(names: &[&str], not_after: u64) -> (Vec<u8>, Vec<u8>) {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        params.name_constraints = Some(NameConstraints {
            permitted_subtrees: names
                .iter()
                .map(|n| GeneralSubtree::DnsName((*n).to_string()))
                .collect(),
            excluded_subtrees: vec![],
        });
        params.not_after =
            time::OffsetDateTime::from_unix_timestamp(i64::try_from(not_after).unwrap()).unwrap();
        params.not_before = time::OffsetDateTime::from_unix_timestamp(1).unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert.der().to_vec(), key.serialize_der())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bundle_round_trips_and_its_facts_come_from_the_certificate() {
        let (cert, key) = test_ca::mint(&["api.test", "Link-7.pods"], 4_000_000_000);
        let ca = PodCa::from_bundle(&PodCa::to_bundle(&cert, &key)).unwrap();
        assert_eq!(ca.permitted(), ["api.test", "link-7.pods"]);
        assert_eq!(ca.not_after(), 4_000_000_000);
        assert!(ca.name_permitted("API.test"));
        assert!(!ca.name_permitted("sub.api.test"), "exact names only");
        assert!(
            format!("{ca:?}").find("key").is_none(),
            "the key is never printed"
        );
    }

    /// The bundle is read off the head of the decision channel and not one
    /// byte more: what follows is the decision protocol's.
    #[test]
    fn read_bundle_takes_exactly_the_bundle_from_the_channel() {
        let (cert, key) = test_ca::mint(&["api.test"], 4_000_000_000);
        let bundle = PodCa::to_bundle(&cert, &key);
        let mut channel = bundle.clone();
        channel.extend_from_slice(b"NEXT-FRAME");
        let mut reader = std::io::Cursor::new(channel);
        assert_eq!(read_bundle(&mut reader).unwrap(), bundle);
        let mut rest = Vec::new();
        std::io::Read::read_to_end(&mut reader, &mut rest).unwrap();
        assert_eq!(rest, b"NEXT-FRAME");
        assert!(PodCa::from_bundle(&bundle).is_ok());
    }

    #[test]
    fn read_bundle_refuses_a_short_a_wrong_or_an_oversized_channel() {
        let (cert, key) = test_ca::mint(&["api.test"], 4_000_000_000);
        let bundle = PodCa::to_bundle(&cert, &key);
        let short = bundle.get(..bundle.len() - 1).unwrap().to_vec();
        assert_eq!(
            read_bundle(&mut std::io::Cursor::new(short)),
            Err(CaError::Bundle)
        );
        assert_eq!(
            read_bundle(&mut std::io::Cursor::new(b"junk".to_vec())),
            Err(CaError::Bundle)
        );
        let mut huge = BUNDLE_MAGIC.to_vec();
        huge.extend_from_slice(&u32::try_from(MAX_BUNDLE).unwrap().to_be_bytes());
        assert_eq!(
            read_bundle(&mut std::io::Cursor::new(huge)),
            Err(CaError::Bundle)
        );
    }

    #[test]
    fn a_ca_that_would_vouch_for_any_name_is_refused() {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).unwrap();
        let bundle = PodCa::to_bundle(cert.der(), &key.serialize_der());
        assert_eq!(
            PodCa::from_bundle(&bundle).unwrap_err(),
            CaError::NoNameConstraints
        );
        assert_eq!(PodCa::from_bundle(b"junk").unwrap_err(), CaError::Bundle);
    }
}
