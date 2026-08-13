//! Call SPIFFE agents anywhere over iroh.
//!
//! A relying party reaches an agent by its **SPIFFE identity**, dials it P2P (iroh
//! dial-by-key + NAT traversal), and authenticates it — with no trust placed in how
//! it found the address. The chain of trust, verified at connect time:
//!
//! ```text
//! trust-domain CA  --signs-->  SVID over passport key P for spiffe://…
//! passport key P   --signs-->  NodeBinding: "P controls iroh NodeId N"
//! iroh connect to N            proves control of transport key N
//! => the peer reached at this connection IS spiffe://…, rooted in the CA
//! ```
//!
//! # The directory is untrusted
//!
//! [`SpiffeDirectory`] maps a SPIFFE ID to a reachable iroh address, but a wrong or
//! malicious mapping is caught by [`authenticate_hail`]: you dial, the peer proves an
//! SVID that names the requested principal AND a binding for the exact `NodeId` you
//! dialed, or the call fails. The directory is therefore an availability hint, not a
//! security boundary — location and identity are cleanly separated.
//!
//! # Composability
//!
//! The passport key is the stable, attestable identity; the iroh node key is a
//! separate transport key it vouches for (so transport keys may rotate). A caller
//! sets a `min_assurance` floor: above `L0Bearer` the SVID must clear it, scored by
//! the same [`effective_assurance`] the tool-proxy relying-party gate uses (North
//! Star C9) — launch measurement is `L1Software`, TPM residency composes here, and
//! an `L2Device` floor refuses every peer until the EK-manufacturer root lands.
//!
//! # Stability
//!
//! The ALPN and `Hail` wire format are **INTERNAL / unstable** — not a committed
//! external interface. Freezing them for interoperability is a separate decision.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, bail, Result};
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointAddr};
use nucleus_identity::{
    tpm_devid::effective_assurance, AssuranceLevel, AttestationRequirements, SelfMeasuredBackend,
    SvidAttestationBackend, TrustBundle, VerifiedAttestation,
};
use nucleus_node_binding::{verify_binding, NodeBinding};
use serde::{Deserialize, Serialize};

/// ALPN for the SPIFFE hail protocol. INTERNAL / unstable.
pub const ALPN: &[u8] = b"nucleus-spiffe-hail/1";

/// What an agent presents on the wire: its SVID chain and the `NodeId` binding.
#[derive(Clone, Serialize, Deserialize)]
pub struct Hail {
    /// PEM certificate chain of the agent's SVID (leaf first).
    pub svid_chain_pem: String,
    /// Signed statement that the SVID's passport key controls the agent's `NodeId`.
    pub binding: NodeBinding,
}

/// A peer authenticated by SPIFFE identity over an iroh connection.
#[derive(Debug, Clone)]
pub struct VerifiedPeer {
    /// The CA-verified SPIFFE ID of the peer.
    pub spiffe_id: String,
    /// The iroh `NodeId` the connection is actually to, bound to `spiffe_id`.
    pub node_id: [u8; 32],
    /// The peer's attestation, when one was required and verified.
    pub attestation: Option<VerifiedAttestation>,
}

/// Resolves a SPIFFE ID to a reachable iroh address.
///
/// **Untrusted:** a wrong mapping is caught by [`authenticate_hail`], so this only
/// affects reachability, never authentication.
pub trait SpiffeDirectory: Send + Sync {
    /// The last-known address for `spiffe_id`, if any.
    fn resolve(&self, spiffe_id: &str) -> Option<EndpointAddr>;
}

/// An in-memory directory populated by an operator or control plane.
#[derive(Default, Clone)]
pub struct InMemoryDirectory(HashMap<String, EndpointAddr>);

impl InMemoryDirectory {
    /// A new, empty directory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Advertise `addr` as the reachable address for `spiffe_id`.
    pub fn register(&mut self, spiffe_id: impl Into<String>, addr: EndpointAddr) {
        self.0.insert(spiffe_id.into(), addr);
    }
}

impl SpiffeDirectory for InMemoryDirectory {
    fn resolve(&self, spiffe_id: &str) -> Option<EndpointAddr> {
        self.0.get(spiffe_id).cloned()
    }
}

/// The server side: serves this agent's [`Hail`] to any caller on the ALPN. Mount it
/// on an [`iroh::protocol::Router`] with `.accept(ALPN, handler)`.
#[derive(Clone, Debug)]
pub struct SpiffeHailProtocol {
    hail_json: Arc<Vec<u8>>,
}

impl SpiffeHailProtocol {
    /// Serve `hail` (the agent's SVID + `NodeId` binding) to callers.
    pub fn new(hail: &Hail) -> Result<Self> {
        Ok(Self {
            hail_json: Arc::new(serde_json::to_vec(hail)?),
        })
    }
}

impl ProtocolHandler for SpiffeHailProtocol {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let (mut send, _recv) = connection
            .accept_bi()
            .await
            .map_err(AcceptError::from_err)?;
        send.write_all(&self.hail_json)
            .await
            .map_err(AcceptError::from_err)?;
        send.finish().map_err(AcceptError::from_err)?;
        connection.closed().await;
        Ok(())
    }
}

/// Authenticate a [`Hail`] from a peer reached at `connected_node`.
///
/// This is the pure security decision — no transport — so it is exercised directly in
/// tests. It asserts, in order: the SVID chains to a trusted CA root and names the
/// requested principal; the binding is signed by the SVID's passport key, is for that
/// principal, and is for the exact `NodeId` dialed (anti-replay); and that the peer's
/// SVID clears the caller's `min_assurance` floor.
///
/// The floor reuses [`effective_assurance`] — the *same* North Star C9 decision the
/// tool-proxy relying-party gate enforces — so calling an agent over iroh applies the
/// identical assurance semantics as reaching one locally. `L0Bearer` imposes no floor;
/// a floor above it requires a verifiable attestation and fails closed on an
/// absent/invalid/replayed one. Residency-rooted evidence on the SVID raises the level;
/// a floor of `L2Device` refuses every peer until the EK-manufacturer root lands.
pub fn authenticate_hail(
    hail: &Hail,
    connected_node: [u8; 32],
    trust_bundle: &TrustBundle,
    requested_spiffe_id: &str,
    min_assurance: AssuranceLevel,
) -> Result<VerifiedPeer> {
    let (svid_id, passport_pk, leaf_der) = verify_svid_chain(&hail.svid_chain_pem, trust_bundle)?;
    if svid_id != requested_spiffe_id {
        bail!("SVID is for {svid_id}, not the requested {requested_spiffe_id}");
    }

    verify_binding(&hail.binding, &passport_pk).map_err(|e| anyhow!("node binding: {e}"))?;
    if hail.binding.principal != svid_id {
        bail!(
            "binding principal {} does not match the SVID {svid_id}",
            hail.binding.principal
        );
    }
    if hail.binding.node_id != connected_node {
        bail!("binding is for a different NodeId than the connection (possible replay)");
    }

    let attestation = if min_assurance > AssuranceLevel::L0Bearer {
        // Require a verifiable software attestation (fail-closed) as the launch base,
        let attestation = SelfMeasuredBackend
            .verify_svid(&hail.svid_chain_pem, &AttestationRequirements::any(), true)
            .map_err(|e| anyhow!("attestation required but not verified: {e}"))?;
        // then raise the level by any TPM residency evidence and enforce the floor.
        let level = effective_assurance(&leaf_der, attestation.is_some())
            .map_err(|e| anyhow!("residency evidence invalid: {e}"))?;
        if level < min_assurance {
            bail!("peer assurance {level:?} is below the required floor {min_assurance:?}");
        }
        attestation
    } else {
        None
    };

    Ok(VerifiedPeer {
        spiffe_id: svid_id,
        node_id: connected_node,
        attestation,
    })
}

/// Call a SPIFFE agent by identity: resolve via the directory, dial it P2P over iroh,
/// and authenticate the peer. Returns the live connection and the verified identity.
pub async fn call_spiffe(
    endpoint: &Endpoint,
    directory: &dyn SpiffeDirectory,
    spiffe_id: &str,
    trust_bundle: &TrustBundle,
    min_assurance: AssuranceLevel,
) -> Result<(Connection, VerifiedPeer)> {
    let addr = directory
        .resolve(spiffe_id)
        .ok_or_else(|| anyhow!("{spiffe_id} is not in the directory"))?;
    let conn = endpoint
        .connect(addr, ALPN)
        .await
        .map_err(|e| anyhow!("dial failed: {e}"))?;
    let connected_node = *conn.remote_id().as_bytes();

    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| anyhow!("open stream: {e}"))?;
    send.finish().map_err(|e| anyhow!("finish: {e}"))?;
    let bytes = recv
        .read_to_end(256 * 1024)
        .await
        .map_err(|e| anyhow!("read hail: {e}"))?;
    let hail: Hail = serde_json::from_slice(&bytes)?;

    let peer = authenticate_hail(
        &hail,
        connected_node,
        trust_bundle,
        spiffe_id,
        min_assurance,
    )?;
    Ok((conn, peer))
}

/// Verify an SVID chain to the trust bundle; returns
/// `(spiffe_id, ed25519 passport pk, leaf DER)`. The leaf DER is returned so the
/// caller can derive the peer's assurance level ([`effective_assurance`]) without
/// re-parsing the PEM.
fn verify_svid_chain(
    chain_pem: &str,
    trust_bundle: &TrustBundle,
) -> Result<(String, [u8; 32], Vec<u8>)> {
    use x509_parser::prelude::{FromDer, X509Certificate};

    let (_, leaf_pem) = x509_parser::pem::parse_x509_pem(chain_pem.as_bytes())
        .map_err(|e| anyhow!("SVID PEM parse: {e}"))?;
    let leaf = leaf_pem
        .parse_x509()
        .map_err(|e| anyhow!("SVID X.509 parse: {e}"))?;

    let mut signed_by_root = false;
    for root in trust_bundle.roots() {
        let (_, root_cert) =
            X509Certificate::from_der(root.der()).map_err(|e| anyhow!("CA root parse: {e}"))?;
        if leaf.verify_signature(Some(root_cert.public_key())).is_ok() {
            signed_by_root = true;
            break;
        }
    }
    if !signed_by_root {
        bail!("SVID leaf is not signed by any trusted CA root");
    }

    let spiffe_id = leaf
        .subject_alternative_name()
        .ok()
        .flatten()
        .and_then(|san| {
            san.value.general_names.iter().find_map(|gn| match gn {
                x509_parser::extensions::GeneralName::URI(u) if u.starts_with("spiffe://") => {
                    Some(u.to_string())
                }
                _ => None,
            })
        })
        .ok_or_else(|| anyhow!("SVID has no spiffe:// URI SAN"))?;

    // The leaf's ed25519 public key is the trailing 32 bytes of its SPKI.
    let raw = leaf.public_key().raw;
    if raw.len() < 32 {
        bail!("SVID SPKI is too short for an ed25519 key");
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&raw[raw.len() - 32..]);
    Ok((spiffe_id, pk, leaf_pem.contents))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use nucleus_identity::{CaClient, Identity, SelfSignedCa};
    use nucleus_node_binding::sign_binding;
    use std::time::Duration;

    /// Extract the 32-byte ed25519 seed from a PKCS#8 DER (bytes after the first `04 20`).
    fn ed25519_seed(pkcs8: &[u8]) -> [u8; 32] {
        let pos = pkcs8
            .windows(2)
            .position(|w| w == [0x04, 0x20])
            .expect("ed25519 pkcs8");
        pkcs8[pos + 2..pos + 2 + 32].try_into().unwrap()
    }

    /// Mint an ed25519 SVID over a fresh passport key for `spiffe_uri`, signed by
    /// `ca`. Returns `(chain_pem, canonical_spiffe_id, passport signing key)`.
    async fn mint(ca: &SelfSignedCa, spiffe_uri: &str) -> (String, String, SigningKey) {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let sk = SigningKey::from_bytes(&ed25519_seed(&kp.serialize_der()));
        let identity = Identity::from_spiffe_uri(spiffe_uri).unwrap();
        let canonical = identity.to_spiffe_uri();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = vec![rcgen::SanType::URI(
            rcgen::string::Ia5String::try_from(canonical.clone()).unwrap(),
        )];
        let csr = params.serialize_request(&kp).unwrap().pem().unwrap();
        let cert = ca
            .sign_csr(
                &csr,
                &kp.serialize_pem(),
                &identity,
                Duration::from_secs(3600),
            )
            .await
            .unwrap();
        (cert.chain_pem(), canonical, sk)
    }

    /// Like [`mint`], but the SVID carries a verifiable launch attestation
    /// (`SelfMeasuredBackend` → `L1Software`), for exercising the assurance floor's
    /// admit path.
    async fn mint_attested(ca: &SelfSignedCa, spiffe_uri: &str) -> (String, String, SigningKey) {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let sk = SigningKey::from_bytes(&ed25519_seed(&kp.serialize_der()));
        let identity = Identity::from_spiffe_uri(spiffe_uri).unwrap();
        let canonical = identity.to_spiffe_uri();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = vec![rcgen::SanType::URI(
            rcgen::string::Ia5String::try_from(canonical.clone()).unwrap(),
        )];
        let csr = params.serialize_request(&kp).unwrap().pem().unwrap();
        let att = nucleus_identity::LaunchAttestation::from_hashes([7u8; 32], [8u8; 32], [9u8; 32]);
        let cert = ca
            .sign_attested_csr(
                &csr,
                &kp.serialize_pem(),
                &identity,
                Duration::from_secs(3600),
                &att,
            )
            .await
            .unwrap();
        (cert.chain_pem(), canonical, sk)
    }

    fn hail(chain: &str, node: [u8; 32], principal: &str, sk: &SigningKey) -> Hail {
        Hail {
            svid_chain_pem: chain.to_string(),
            binding: sign_binding(&node, principal, sk),
        }
    }

    /// The control: a CA-rooted SVID + a binding for the dialed node authenticates.
    #[tokio::test]
    async fn authenticates_a_bound_svid() {
        let ca = SelfSignedCa::new("demo").unwrap();
        let (chain, id, sk) = mint(&ca, "spiffe://demo/agent-x").await;
        let node = [11u8; 32];
        let peer = authenticate_hail(
            &hail(&chain, node, &id, &sk),
            node,
            ca.trust_bundle(),
            &id,
            AssuranceLevel::L0Bearer,
        )
        .expect("verifies");
        assert_eq!(peer.spiffe_id, id);
        assert_eq!(peer.node_id, node);
        assert!(peer.attestation.is_none());
    }

    /// Anti-replay: a valid binding for a DIFFERENT node must not authenticate this
    /// connection.
    #[tokio::test]
    async fn rejects_a_binding_for_a_different_node() {
        let ca = SelfSignedCa::new("demo").unwrap();
        let (chain, id, sk) = mint(&ca, "spiffe://demo/agent-x").await;
        let h = hail(&chain, [11u8; 32], &id, &sk);
        let err = authenticate_hail(
            &h,
            [22u8; 32],
            ca.trust_bundle(),
            &id,
            AssuranceLevel::L0Bearer,
        )
        .unwrap_err();
        assert!(err.to_string().contains("different NodeId"), "{err}");
    }

    /// The SVID must name the principal the caller asked for.
    #[tokio::test]
    async fn rejects_an_svid_for_the_wrong_principal() {
        let ca = SelfSignedCa::new("demo").unwrap();
        let (chain, id, sk) = mint(&ca, "spiffe://demo/agent-x").await;
        let node = [11u8; 32];
        let err = authenticate_hail(
            &hail(&chain, node, &id, &sk),
            node,
            ca.trust_bundle(),
            "spiffe://demo/ns/default/sa/someone-else",
            AssuranceLevel::L0Bearer,
        )
        .unwrap_err();
        assert!(err.to_string().contains("not the requested"), "{err}");
    }

    /// An SVID from an untrusted CA is refused.
    #[tokio::test]
    async fn rejects_an_svid_not_signed_by_the_trusted_ca() {
        let ca = SelfSignedCa::new("demo").unwrap();
        let stranger = SelfSignedCa::new("demo").unwrap();
        let (chain, id, sk) = mint(&ca, "spiffe://demo/agent-x").await;
        let node = [11u8; 32];
        let err = authenticate_hail(
            &hail(&chain, node, &id, &sk),
            node,
            stranger.trust_bundle(),
            &id,
            AssuranceLevel::L0Bearer,
        )
        .unwrap_err();
        assert!(err.to_string().contains("not signed"), "{err}");
    }

    /// A binding not signed by the SVID's passport key is refused.
    #[tokio::test]
    async fn rejects_a_binding_not_signed_by_the_passport() {
        let ca = SelfSignedCa::new("demo").unwrap();
        let (chain, id, _sk) = mint(&ca, "spiffe://demo/agent-x").await;
        let node = [11u8; 32];
        let forger = SigningKey::from_bytes(&[9u8; 32]);
        let err = authenticate_hail(
            &hail(&chain, node, &id, &forger),
            node,
            ca.trust_bundle(),
            &id,
            AssuranceLevel::L0Bearer,
        )
        .unwrap_err();
        assert!(err.to_string().contains("node binding"), "{err}");
    }

    /// An `L1Software` floor fails closed on a plain (unattested) SVID.
    #[tokio::test]
    async fn an_l1_floor_fails_closed_on_a_plain_svid() {
        let ca = SelfSignedCa::new("demo").unwrap();
        let (chain, id, sk) = mint(&ca, "spiffe://demo/agent-x").await;
        let node = [11u8; 32];
        let err = authenticate_hail(
            &hail(&chain, node, &id, &sk),
            node,
            ca.trust_bundle(),
            &id,
            AssuranceLevel::L1Software,
        )
        .unwrap_err();
        assert!(err.to_string().contains("attestation required"), "{err}");
    }

    /// An `L1Software` floor ADMITS an attested SVID (the positive teeth), and the
    /// verified attestation rides along on the peer.
    #[tokio::test]
    async fn an_l1_floor_admits_an_attested_svid() {
        let ca = SelfSignedCa::new("demo").unwrap();
        let (chain, id, sk) = mint_attested(&ca, "spiffe://demo/agent-x").await;
        let node = [11u8; 32];
        let peer = authenticate_hail(
            &hail(&chain, node, &id, &sk),
            node,
            ca.trust_bundle(),
            &id,
            AssuranceLevel::L1Software,
        )
        .expect("an attested SVID clears an L1 floor");
        assert_eq!(peer.spiffe_id, id);
        assert!(peer.attestation.is_some(), "attestation must ride along");
    }

    /// An `L2Device` floor REFUSES an attested SVID: self-measured attestation tops
    /// out at L1Software, so calling over iroh never over-admits an L2 claim the
    /// evidence cannot back (genuine-silicon needs the EK root, a later increment) —
    /// the identical never-over-admit property the tool-proxy floor enforces.
    #[tokio::test]
    async fn an_l2_floor_refuses_a_merely_software_attested_svid() {
        let ca = SelfSignedCa::new("demo").unwrap();
        let (chain, id, sk) = mint_attested(&ca, "spiffe://demo/agent-x").await;
        let node = [11u8; 32];
        let err = authenticate_hail(
            &hail(&chain, node, &id, &sk),
            node,
            ca.trust_bundle(),
            &id,
            AssuranceLevel::L2Device,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("below the required floor"),
            "{err}"
        );
    }

    /// The full path over a live iroh connection. Ignored in CI (live QUIC between two
    /// endpoints is flaky under sandboxed networking); compiled there, run manually
    /// with `cargo test -p nucleus-spiffe-hail -- --ignored`.
    #[tokio::test]
    #[ignore = "live QUIC between two iroh endpoints; compiled in CI, run manually"]
    async fn end_to_end_call_over_iroh() -> Result<()> {
        use iroh::{endpoint::presets, protocol::Router, SecretKey};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = SelfSignedCa::new("demo").unwrap();
        let (chain, id, sk) = mint(&ca, "spiffe://demo/agent-x").await;

        let node_secret = SecretKey::from_bytes(&[11u8; 32]);
        let node_id = *node_secret.public().as_bytes();
        let h = hail(&chain, node_id, &id, &sk);

        let server = Endpoint::builder(presets::N0DisableRelay)
            .secret_key(node_secret)
            .bind()
            .await?;
        let _router = Router::builder(server.clone())
            .accept(ALPN, SpiffeHailProtocol::new(&h)?)
            .spawn();

        let mut dir = InMemoryDirectory::new();
        dir.register(&id, server.addr());

        let client = Endpoint::builder(presets::N0DisableRelay).bind().await?;
        let (_conn, peer) = call_spiffe(
            &client,
            &dir,
            &id,
            ca.trust_bundle(),
            AssuranceLevel::L0Bearer,
        )
        .await?;
        assert_eq!(peer.spiffe_id, id);
        assert_eq!(peer.node_id, node_id);
        Ok(())
    }
}
