//! SPIKE — the FULL "call SPIFFE agents anywhere" chain over iroh.
//!
//! Extends `spiffe_iroh_spike` from a hand-trusted passport key to a real
//! CA-rooted SVID, and adds a SPIFFE-ID → address directory so a caller
//! *addresses an agent by its SPIFFE ID*, not an out-of-band NodeAddr.
//!
//! Chain of trust demonstrated end to end:
//!   trust-domain CA  --signs-->  SVID over passport key P for spiffe://demo/agent-x
//!   passport key P   --signs-->  NodeBinding: "P controls iroh NodeId N"
//!   iroh connect to N            proves control of transport key N
//!   => a caller who trusts the CA reaches N and knows it IS spiffe://demo/agent-x
//!
//! The passport key (the SVID subject) is the stable, attestable identity; the iroh
//! node key is a separate transport key it vouches for. The TPM DevID work can
//! attest P is hardware-resident; `SvidAttestationBackend` composes on top to add
//! attestation checks. Run: `cargo run -p nucleus-cli --example spiffe_iroh_full`.

use std::collections::HashMap;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use iroh::{endpoint::presets, Endpoint, EndpointAddr, SecretKey};
use nucleus_identity::{CaClient, Identity, SelfSignedCa};
use nucleus_node_binding::{sign_binding, verify_binding, NodeBinding};
use serde::{Deserialize, Serialize};

const ALPN: &[u8] = b"nucleus-spiffe-hail/1";
const TRUST_DOMAIN: &str = "demo";
const PRINCIPAL: &str = "spiffe://demo/agent-x";

/// What an agent presents on the wire: its SVID chain + the NodeId binding.
#[derive(Serialize, Deserialize)]
struct Hail {
    svid_chain_pem: String,
    binding: NodeBinding,
}

/// Minimal "address by identity" directory: SPIFFE ID → reachable iroh address.
#[derive(Default)]
struct SpiffeDirectory(HashMap<String, EndpointAddr>);
impl SpiffeDirectory {
    fn register(&mut self, spiffe_id: &str, addr: EndpointAddr) {
        self.0.insert(spiffe_id.to_string(), addr);
    }
    fn resolve(&self, spiffe_id: &str) -> Option<EndpointAddr> {
        self.0.get(spiffe_id).cloned()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ── Trust domain: one CA everyone trusts ──
    let ca = SelfSignedCa::new(TRUST_DOMAIN).map_err(|e| anyhow::anyhow!("{e}"))?;

    // ── Agent: passport (identity) key P, SVID over P, iroh transport key N ──
    let passport_kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let passport_seed = ed25519_seed(&passport_kp.serialize_der())?;
    let passport_sk = SigningKey::from_bytes(&passport_seed);

    // The CA canonicalizes SPIFFE URIs (ns/sa form); use that everywhere.
    let (svid, principal) = issue_svid(&ca, &passport_kp, PRINCIPAL).await?;

    let node_secret = SecretKey::from_bytes(&[11u8; 32]);
    let node_id = *node_secret.public().as_bytes();
    let binding = sign_binding(&node_id, &principal, &passport_sk);

    // ── Agent endpoint serves its hail on the ALPN ──
    let server = Endpoint::builder(presets::N0)
        .secret_key(node_secret)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await?;
    let mut directory = SpiffeDirectory::default();
    directory.register(&principal, server.addr());

    let hail = serde_json::to_vec(&Hail {
        svid_chain_pem: svid,
        binding,
    })?;
    let server_task = tokio::spawn(async move {
        let conn = server
            .accept()
            .await
            .ok_or_else(|| anyhow::anyhow!("no incoming"))?
            .await?;
        let (mut send, _r) = conn.accept_bi().await?;
        send.write_all(&hail).await?;
        send.finish()?;
        conn.closed().await;
        Ok::<_, anyhow::Error>(())
    });

    // ── Caller: "call spiffe://demo/agent-x" — resolve, dial, verify ──
    let ca_roots = ca.trust_bundle().clone();
    let client = Endpoint::builder(presets::N0).bind().await?;

    let addr = directory
        .resolve(&principal)
        .ok_or_else(|| anyhow::anyhow!("{principal} not in directory"))?;
    let conn = client.connect(addr, ALPN).await?;
    let connected_node = *conn.remote_id().as_bytes();

    let (mut send, mut recv) = conn.open_bi().await?;
    send.finish()?;
    let hail: Hail = serde_json::from_slice(&recv.read_to_end(256 * 1024).await?)?;

    // (1) SVID: chains to the CA, and names the principal we asked for. Yields P.
    let (svid_spiffe_id, passport_pk) = verify_svid(&hail.svid_chain_pem, &ca_roots)?;
    anyhow::ensure!(
        svid_spiffe_id == principal,
        "SVID is for a different principal"
    );
    // (2) Binding: P vouches for this transport key, for THIS principal, and it's
    //     the key we actually dialed.
    verify_binding(&hail.binding, &passport_pk)?;
    anyhow::ensure!(
        hail.binding.principal == svid_spiffe_id,
        "binding principal != SVID"
    );
    anyhow::ensure!(
        hail.binding.node_id == connected_node,
        "binding is for a different NodeId than the live connection"
    );

    println!("✅ called {principal} by identity → resolved → dialed over iroh");
    println!(
        "   SVID verified to CA '{TRUST_DOMAIN}'; passport vouches for this exact transport key"
    );

    // Negative: an SVID for a different principal must not authenticate this call.
    let imposter_kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let (imposter, _) = issue_svid(&ca, &imposter_kp, "spiffe://demo/somebody-else").await?;
    let (imposter_id, _) = verify_svid(&imposter, &ca_roots)?;
    anyhow::ensure!(
        imposter_id != principal,
        "imposter must not match the requested principal"
    );
    println!(
        "✅ negative control: a CA-valid SVID for a different principal is refused for this call"
    );

    server_task.await??;
    Ok(())
}

/// Issues an ed25519 SVID over `kp` for `spiffe_uri`, signed by `ca`. Returns the
/// chain PEM and the CA-canonicalized SPIFFE ID actually embedded.
async fn issue_svid(
    ca: &SelfSignedCa,
    kp: &rcgen::KeyPair,
    spiffe_uri: &str,
) -> anyhow::Result<(String, String)> {
    let identity = Identity::from_spiffe_uri(spiffe_uri).map_err(|e| anyhow::anyhow!("{e}"))?;
    let canonical = identity.to_spiffe_uri();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    params.subject_alt_names = vec![rcgen::SanType::URI(rcgen::string::Ia5String::try_from(
        canonical.clone(),
    )?)];
    let csr_pem = params.serialize_request(kp)?.pem()?;
    let cert = ca
        .sign_csr(
            &csr_pem,
            &kp.serialize_pem(),
            &identity,
            Duration::from_secs(3600),
        )
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok((cert.chain_pem(), canonical))
}

/// Verifies an SVID chain to the CA trust bundle; returns (spiffe_id, passport pubkey).
fn verify_svid(
    chain_pem: &str,
    ca_roots: &nucleus_identity::TrustBundle,
) -> anyhow::Result<(String, [u8; 32])> {
    use x509_parser::prelude::{FromDer, X509Certificate};

    let (_, leaf_pem) = x509_parser::pem::parse_x509_pem(chain_pem.as_bytes())?;
    let leaf = leaf_pem.parse_x509()?;

    // Chain: the leaf must be signed by a CA root we trust.
    let mut signed_by_root = false;
    for root in ca_roots.roots() {
        let (_, root_cert) = X509Certificate::from_der(root.der())?;
        if leaf.verify_signature(Some(root_cert.public_key())).is_ok() {
            signed_by_root = true;
            break;
        }
    }
    anyhow::ensure!(
        signed_by_root,
        "SVID leaf is not signed by a trusted CA root"
    );

    // SPIFFE ID from the URI SAN.
    let spiffe_id = leaf
        .subject_alternative_name()?
        .and_then(|san| {
            san.value.general_names.iter().find_map(|gn| match gn {
                x509_parser::extensions::GeneralName::URI(u) if u.starts_with("spiffe://") => {
                    Some(u.to_string())
                }
                _ => None,
            })
        })
        .ok_or_else(|| anyhow::anyhow!("SVID has no SPIFFE URI SAN"))?;

    let passport_pk = public_key_from_spki(leaf.public_key().raw)?;
    Ok((spiffe_id, passport_pk))
}

/// Extracts the 32-byte ed25519 public key from a SubjectPublicKeyInfo DER (the key
/// is its trailing 32 bytes).
fn public_key_from_spki(spki_der: &[u8]) -> anyhow::Result<[u8; 32]> {
    anyhow::ensure!(spki_der.len() >= 32, "SPKI too short for ed25519");
    Ok(spki_der[spki_der.len() - 32..].try_into()?)
}

/// Extracts the 32-byte ed25519 seed from a PKCS#8 DER (the private key OCTET STRING
/// content, i.e. the 32 bytes following the first `04 20`).
fn ed25519_seed(pkcs8_der: &[u8]) -> anyhow::Result<[u8; 32]> {
    let pos = pkcs8_der
        .windows(2)
        .position(|w| w == [0x04, 0x20])
        .ok_or_else(|| anyhow::anyhow!("no ed25519 private-key octet string in PKCS#8"))?;
    let start = pos + 2;
    Ok(pkcs8_der
        .get(start..start + 32)
        .ok_or_else(|| anyhow::anyhow!("truncated PKCS#8 seed"))?
        .try_into()?)
}
