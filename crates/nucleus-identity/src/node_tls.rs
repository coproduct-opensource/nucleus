//! The TLS client configuration every node-facing client uses.
//!
//! A node's certificate is an X.509-SVID: its identity is one SPIFFE URI SAN,
//! `spiffe://<trust-domain>/ns/system/sa/node` ([`Identity::node`]), and it
//! carries no DNS or IP SAN. Standard hostname verification therefore cannot
//! identify it. What identifies it is that URI, so that is what this module
//! checks in place of the hostname.
//!
//! [`NodeServerVerifier`] wraps rustls' standard WebPKI verifier:
//!
//! 1. the chain must build to the pinned roots, be in date and carry
//!    `serverAuth` — the inner verifier decides this, unchanged;
//! 2. the server-name comparison is the one result it ignores, because the
//!    name a client dialled (`127.0.0.1`, a hostname) is not the node's
//!    identity;
//! 3. the leaf must be a well-formed SVID ([`spiffe_uri_from_svid`]: exactly
//!    one URI SAN, not a CA) whose URI is EXACTLY the expected node's.
//!
//! The same CA that issues the node's certificate issues every pod's. Chain
//! validation alone therefore says "someone this CA certified", not "the node";
//! step 3 is what says "the node".
//!
//! [`node_client_config`] is the one constructor a client needs: it reads the
//! client's own SVID and the trust bundle, and derives the node it may talk to
//! from the client's trust domain. A node only certifies identities in its own
//! trust domain, so a client that holds a certificate from that node's CA
//! already names the domain whose node it expects.

use crate::certificate::{TrustBundle, spiffe_uri_from_svid};
use crate::identity::Identity;
use crate::tls::root_store_from_trust_bundle;
use crate::{Error, Result};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use std::sync::Arc;

/// A `ServerCertVerifier` that accepts exactly one SPIFFE identity.
///
/// Chain, validity and key usage are decided by rustls' own
/// [`WebPkiServerVerifier`]; this type adds the identity check that replaces
/// the hostname check, and nothing else.
#[derive(Debug)]
pub struct NodeServerVerifier {
    inner: Arc<WebPkiServerVerifier>,
    expected: String,
}

impl NodeServerVerifier {
    /// A verifier that accepts only a certificate chaining to `roots` whose
    /// SVID names `expected`.
    ///
    /// # Errors
    ///
    /// When `roots` is empty or unusable: a verifier with no anchors could
    /// only ever refuse, and building one is a configuration error.
    pub fn new(roots: Arc<RootCertStore>, expected: &Identity) -> Result<Self> {
        let inner = WebPkiServerVerifier::builder_with_provider(
            roots,
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .map_err(|e| Error::Certificate(format!("failed to build server verifier: {e}")))?;
        Ok(Self {
            inner,
            expected: expected.to_spiffe_uri(),
        })
    }

    /// The SPIFFE ID this verifier accepts.
    pub fn expected(&self) -> &str {
        &self.expected
    }
}

impl ServerCertVerifier for NodeServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        // rustls validates the chain (anchors, dates, EKU, revocation) BEFORE it
        // compares names, so a name error is only ever reached by a chain that
        // already verified. Every other error is final.
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(_)
            | Err(rustls::Error::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
            )) => {}
            Err(e) => return Err(e),
        }

        let refuse =
            || rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure);
        let presented = spiffe_uri_from_svid(end_entity.as_ref()).map_err(|e| {
            tracing::debug!(error = %e, expected = %self.expected, "server certificate is not an SVID");
            refuse()
        })?;
        if presented != self.expected {
            tracing::debug!(%presented, expected = %self.expected, "server certificate names another identity");
            return Err(refuse());
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// The client TLS configuration for reaching a node.
///
/// `identity_pem` is the client's SVID chain and private key in one buffer
/// (the convention `reqwest::Identity::from_pem` uses); `trust_bundle_pem` is
/// the node's CA. The node accepted is [`Identity::node`] in the trust domain
/// of the client's own SVID.
///
/// Hand the result to `reqwest`'s `tls_backend_preconfigured`.
///
/// # Errors
///
/// When either PEM is malformed, when `identity_pem` holds no certificate or
/// not exactly one private key, when the client's leaf is not an SVID (so no
/// trust domain, and no node, can be named), or when the bundle holds no root.
pub fn node_client_config(identity_pem: &[u8], trust_bundle_pem: &[u8]) -> Result<ClientConfig> {
    let (chain, key) = parse_identity(identity_pem)?;
    let own = Identity::from_spiffe_uri(&spiffe_uri_from_svid(chain[0].as_ref())?)?;
    let node = Identity::node(own.trust_domain())?;
    client_config_for(&node, chain, key, trust_bundle_pem)
}

/// [`node_client_config`] for a caller that names the node itself.
///
/// # Errors
///
/// As [`node_client_config`], less the derivation of the node.
pub fn node_client_config_for(
    node: &Identity,
    identity_pem: &[u8],
    trust_bundle_pem: &[u8],
) -> Result<ClientConfig> {
    let (chain, key) = parse_identity(identity_pem)?;
    client_config_for(node, chain, key, trust_bundle_pem)
}

fn client_config_for(
    node: &Identity,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    trust_bundle_pem: &[u8],
) -> Result<ClientConfig> {
    let bundle = TrustBundle::from_pem(
        std::str::from_utf8(trust_bundle_pem)
            .map_err(|e| Error::Certificate(format!("trust bundle is not UTF-8: {e}")))?,
    )?;
    let roots = Arc::new(root_store_from_trust_bundle(&bundle)?);
    let verifier = NodeServerVerifier::new(roots, node)?;
    ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Certificate(format!("failed to select TLS versions: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(chain, key)
        .map_err(|e| Error::Certificate(format!("failed to build client config: {e}")))
}

/// Splits a combined certificate-chain-and-key PEM buffer.
fn parse_identity(pem: &[u8]) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let blocks = pem::parse_many(pem)
        .map_err(|e| Error::Certificate(format!("failed to parse client identity PEM: {e}")))?;
    let mut chain = Vec::new();
    let mut keys = Vec::new();
    for block in blocks {
        match block.tag() {
            "CERTIFICATE" => chain.push(CertificateDer::from(block.into_contents())),
            "PRIVATE KEY" => keys.push(PrivateKeyDer::Pkcs8(block.into_contents().into())),
            "EC PRIVATE KEY" => keys.push(PrivateKeyDer::Sec1(block.into_contents().into())),
            "RSA PRIVATE KEY" => keys.push(PrivateKeyDer::Pkcs1(block.into_contents().into())),
            _ => {}
        }
    }
    if chain.is_empty() {
        return Err(Error::Certificate(
            "client identity PEM holds no certificate".to_string(),
        ));
    }
    let key = match <[PrivateKeyDer<'static>; 1]>::try_from(keys) {
        Ok([key]) => key,
        Err(keys) => {
            return Err(Error::Certificate(format!(
                "client identity PEM must hold exactly one private key, found {}",
                keys.len()
            )));
        }
    };
    Ok((chain, key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        KeyUsagePurpose, SanType,
    };

    const TD: &str = "nucleus.local";

    struct Ca {
        cert_pem: String,
        key: KeyPair,
    }

    impl Ca {
        fn new() -> Self {
            let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
            let mut params = CertificateParams::new(vec![]).unwrap();
            params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            params.subject_alt_names = vec![SanType::URI(
                rcgen::string::Ia5String::try_from(format!("spiffe://{TD}")).unwrap(),
            )];
            let cert = params.self_signed(&key).unwrap();
            Self {
                cert_pem: cert.pem(),
                key,
            }
        }

        fn roots(&self) -> Arc<RootCertStore> {
            let bundle = TrustBundle::from_pem(&self.cert_pem).unwrap();
            Arc::new(root_store_from_trust_bundle(&bundle).unwrap())
        }

        /// A leaf with the key usages the node's own SVID is minted with, and
        /// whatever SANs the test names.
        fn leaf(&self, sans: Vec<SanType>) -> (CertificateDer<'static>, KeyPair) {
            let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
            let mut params = CertificateParams::new(vec![]).unwrap();
            params.is_ca = IsCa::ExplicitNoCa;
            params.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ];
            params.extended_key_usages = vec![
                ExtendedKeyUsagePurpose::ServerAuth,
                ExtendedKeyUsagePurpose::ClientAuth,
            ];
            params.subject_alt_names = sans;
            let issuer = Issuer::from_ca_cert_pem(&self.cert_pem, &self.key).unwrap();
            let cert = params.signed_by(&key, &issuer).unwrap();
            (cert.der().clone(), key)
        }
    }

    fn uri(id: &Identity) -> SanType {
        SanType::URI(rcgen::string::Ia5String::try_from(id.to_spiffe_uri()).unwrap())
    }

    fn node() -> Identity {
        Identity::node(TD).unwrap()
    }

    fn verify(
        verifier: &NodeServerVerifier,
        leaf: &CertificateDer<'_>,
        name: &str,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let name = ServerName::try_from(name.to_string()).unwrap();
        verifier.verify_server_cert(leaf, &[], &name, &[], UnixTime::now())
    }

    #[test]
    fn the_node_is_recognised_by_the_id_its_certificate_names() {
        let ca = Ca::new();
        let verifier = NodeServerVerifier::new(ca.roots(), &node()).unwrap();
        let (leaf, _) = ca.leaf(vec![uri(&node())]);
        verify(&verifier, &leaf, "127.0.0.1").expect("the node's own certificate");
    }

    #[test]
    fn a_pod_certificate_from_the_same_ca_is_not_the_node() {
        let ca = Ca::new();
        let verifier = NodeServerVerifier::new(ca.roots(), &node()).unwrap();
        let pod = Identity::new(TD, "pods", "550e8400-e29b-41d4-a716-446655440000");
        let (leaf, _) = ca.leaf(vec![uri(&pod)]);
        let err = verify(&verifier, &leaf, "127.0.0.1").unwrap_err();
        assert_eq!(
            err,
            rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
        );
    }

    #[test]
    fn a_certificate_naming_no_spiffe_id_is_not_the_node() {
        let ca = Ca::new();
        let verifier = NodeServerVerifier::new(ca.roots(), &node()).unwrap();
        // A DNS SAN that MATCHES the dialled name: the hostname check passing
        // must not stand in for the identity check.
        let (leaf, _) = ca.leaf(vec![SanType::DnsName(
            rcgen::string::Ia5String::try_from("node.nucleus.local").unwrap(),
        )]);
        assert!(verify(&verifier, &leaf, "node.nucleus.local").is_err());
        let (bare, _) = ca.leaf(vec![]);
        assert!(verify(&verifier, &bare, "127.0.0.1").is_err());
    }

    #[test]
    fn a_certificate_naming_the_node_twice_over_is_not_an_svid() {
        let ca = Ca::new();
        let verifier = NodeServerVerifier::new(ca.roots(), &node()).unwrap();
        let pod = Identity::new(TD, "pods", "p");
        let (leaf, _) = ca.leaf(vec![uri(&pod), uri(&node())]);
        assert!(verify(&verifier, &leaf, "127.0.0.1").is_err());
    }

    #[test]
    fn the_node_id_under_another_ca_is_not_the_node() {
        let ca = Ca::new();
        let other = Ca::new();
        let verifier = NodeServerVerifier::new(ca.roots(), &node()).unwrap();
        let (leaf, _) = other.leaf(vec![uri(&node())]);
        let err = verify(&verifier, &leaf, "127.0.0.1").unwrap_err();
        assert_ne!(
            err,
            rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure),
            "refused by the chain, before any identity is read"
        );
    }

    #[test]
    fn a_node_in_another_trust_domain_is_not_this_node() {
        let ca = Ca::new();
        let verifier = NodeServerVerifier::new(ca.roots(), &node()).unwrap();
        let (leaf, _) = ca.leaf(vec![uri(&Identity::node("elsewhere.local").unwrap())]);
        assert!(verify(&verifier, &leaf, "127.0.0.1").is_err());
    }

    #[test]
    fn an_empty_bundle_builds_no_verifier() {
        assert!(NodeServerVerifier::new(Arc::new(RootCertStore::empty()), &node()).is_err());
    }

    /// The whole path a client takes: its own SVID names the trust domain,
    /// the trust domain names the node, and a real handshake decides.
    #[tokio::test]
    async fn the_client_config_reaches_the_node_and_nothing_else_from_its_ca() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let ca = Ca::new();
        let cli = Identity::new(TD, "system", "cli");
        let (cli_leaf, cli_key) = ca.leaf(vec![uri(&cli)]);
        let mut identity_pem = pem::encode(&pem::Pem::new("CERTIFICATE", cli_leaf.to_vec()));
        identity_pem.push_str(&cli_key.serialize_pem());

        let config = node_client_config(identity_pem.as_bytes(), ca.cert_pem.as_bytes()).unwrap();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

        for (server_id, accepted) in [
            (node(), true),
            (
                Identity::new(TD, "pods", "550e8400-e29b-41d4-a716-446655440000"),
                false,
            ),
        ] {
            let (leaf, key) = ca.leaf(vec![uri(&server_id)]);
            let server = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![leaf], PrivateKeyDer::Pkcs8(key.serialize_der().into()))
            .unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let serve = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.unwrap();
                if let Ok(mut tls) = acceptor.accept(tcp).await {
                    let _ = tls.write_all(b"ok").await;
                    let _ = tls.shutdown().await;
                }
            });

            let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            let name = ServerName::try_from("127.0.0.1").unwrap();
            let outcome = connector.connect(name, tcp).await;
            if accepted {
                let mut buf = Vec::new();
                outcome
                    .expect("the node's certificate completes the handshake")
                    .read_to_end(&mut buf)
                    .await
                    .unwrap();
                assert_eq!(buf, b"ok");
            } else {
                assert!(
                    outcome.is_err(),
                    "{server_id} must not be taken for the node"
                );
            }
            serve.await.unwrap();
        }
    }

    #[test]
    fn a_client_without_an_svid_cannot_name_a_node() {
        let ca = Ca::new();
        let (leaf, key) = ca.leaf(vec![]);
        let mut identity_pem = pem::encode(&pem::Pem::new("CERTIFICATE", leaf.to_vec()));
        identity_pem.push_str(&key.serialize_pem());
        assert!(node_client_config(identity_pem.as_bytes(), ca.cert_pem.as_bytes()).is_err());
    }
}
