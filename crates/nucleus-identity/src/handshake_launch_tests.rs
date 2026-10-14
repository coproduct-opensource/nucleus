//! The handshake verifier's falsifiers (ADR 0016 S4).
//!
//! The decision is `admit_peer_launch`; the handshake is a real
//! `TlsServerConfig` acceptor and a real `TlsClientConfig` client over TCP, so a
//! refusal here is the refusal every mTLS listener built through
//! `TlsServerConfig` gives (the node's HTTPS API and the tool-proxy's mTLS
//! listener, through `MtlsListener`).

use super::*;
use crate::attestation::{PeerLaunch, SvidProfile, UnmeasuredTier, admit_peer_launch};
use crate::ca::{CaClient, MeasuredClaims};
use crate::{CsrOptions, Identity, LaunchAttestation, SelfSignedCa, oid};
use std::time::Duration;

const TD: &str = "handshake.test";

fn pod(name: &str) -> Identity {
    Identity::for_pod(TD, name)
}

fn measured() -> LaunchAttestation {
    LaunchAttestation::from_hashes([1; 32], [2; 32], [3; 32])
}

/// A measured leaf the shipping signing path issues, under `profile`.
async fn measured_leaf(ca: &SelfSignedCa, name: &str, profile: SvidProfile) -> WorkloadCertificate {
    let id = pod(name);
    let csr = CsrOptions::new(id.to_spiffe_uri()).generate().unwrap();
    ca.sign_measured_csr(
        csr.csr(),
        csr.private_key(),
        &id,
        Duration::from_secs(3600),
        &MeasuredClaims {
            attestation: &measured(),
            mediator_key_sha256: None,
            launch_quote_sha256: None,
            isolation_profile: profile,
        },
    )
    .await
    .unwrap()
}

/// A leaf carrying exactly `extensions`: the shapes no shipping path issues.
fn raw_leaf(
    ca: &SelfSignedCa,
    name: &str,
    extensions: &[(&[u64], Vec<u8>)],
) -> WorkloadCertificate {
    let id = pod(name);
    let csr = CsrOptions::new(id.to_spiffe_uri()).generate().unwrap();
    ca.sign_with_raw_extensions(csr.csr(), csr.private_key(), &id, extensions)
        .unwrap()
}

/// An eval-cell leaf with no launch at all: the profile alone.
fn eval_cell_without_launch(ca: &SelfSignedCa) -> WorkloadCertificate {
    raw_leaf(
        ca,
        "eval-no-launch",
        &[(
            oid::OID_NUCLEUS_ISOLATION_PROFILE_TUPLE,
            SvidProfile::EvalCell.extension_value(),
        )],
    )
}

async fn plain_leaf(ca: &SelfSignedCa, id: &Identity) -> WorkloadCertificate {
    let csr = CsrOptions::new(id.to_spiffe_uri()).generate().unwrap();
    ca.sign_csr(csr.csr(), csr.private_key(), id, Duration::from_secs(3600))
        .await
        .unwrap()
}

fn admit(cert: &WorkloadCertificate, ca: &SelfSignedCa) -> crate::Result<PeerLaunch> {
    admit_peer_launch(cert.leaf().der(), &[], ca.trust_bundle())
}

#[tokio::test]
async fn the_issued_profile_is_read_back_from_the_leaf() {
    let ca = SelfSignedCa::new(TD).unwrap();
    for profile in SvidProfile::ALL {
        let leaf = measured_leaf(&ca, profile.as_str(), profile).await;
        assert_eq!(
            crate::extract_isolation_profile(leaf.leaf().der()).unwrap(),
            Some(profile)
        );
    }
    let plain = plain_leaf(&ca, &pod("plain")).await;
    assert_eq!(
        crate::extract_isolation_profile(plain.leaf().der()).unwrap(),
        None
    );
}

/// Non-vacuous: each leaf the node issues is admitted, as what it is.
#[tokio::test]
async fn every_leaf_the_node_issues_is_admitted_as_what_it_is() {
    let ca = SelfSignedCa::new(TD).unwrap();
    let eval = measured_leaf(&ca, "eval", SvidProfile::EvalCell).await;
    assert!(matches!(
        admit(&eval, &ca).unwrap(),
        PeerLaunch::EvalCell(_)
    ));
    let standard = measured_leaf(&ca, "standard", SvidProfile::Standard).await;
    assert!(matches!(
        admit(&standard, &ca).unwrap(),
        PeerLaunch::Standard(_)
    ));
    let id = pod("container");
    let csr = CsrOptions::new(id.to_spiffe_uri()).generate().unwrap();
    let unmeasured = ca
        .sign_unmeasured_csr(
            csr.csr(),
            csr.private_key(),
            &id,
            Duration::from_secs(3600),
            UnmeasuredTier::Container,
        )
        .await
        .unwrap();
    assert!(matches!(
        admit(&unmeasured, &ca).unwrap(),
        PeerLaunch::Unmeasured(UnmeasuredTier::Container)
    ));
    let node = plain_leaf(&ca, &Identity::new(TD, "system", "node")).await;
    assert!(matches!(admit(&node, &ca).unwrap(), PeerLaunch::NoLaunch));
}

/// The decision's refusals, each by name.
#[tokio::test]
async fn an_eval_cell_without_a_verified_launch_is_refused_by_name() {
    let ca = SelfSignedCa::new(TD).unwrap();

    let err = admit(&eval_cell_without_launch(&ca), &ca).expect_err("no launch");
    assert!(
        err.to_string()
            .contains("eval-cell SVID that carries no launch"),
        "{err}"
    );

    let unmeasured = raw_leaf(
        &ca,
        "eval-unmeasured",
        &[
            (
                oid::OID_NUCLEUS_ISOLATION_PROFILE_TUPLE,
                SvidProfile::EvalCell.extension_value(),
            ),
            (
                oid::OID_NUCLEUS_UNMEASURED_LAUNCH_TUPLE,
                UnmeasuredTier::Container.extension_value().unwrap(),
            ),
        ],
    );
    let err = admit(&unmeasured, &ca).expect_err("an unmeasured eval cell");
    assert!(
        err.to_string().contains("unmeasured `container` launch"),
        "{err}"
    );

    // A real eval-cell launch from a CA the bundle does not hold.
    let other = SelfSignedCa::new(TD).unwrap();
    let foreign = measured_leaf(&other, "eval-foreign", SvidProfile::EvalCell).await;
    let err = admit(&foreign, &ca).expect_err("another CA's eval cell");
    assert!(
        err.to_string().contains("not issued by a trusted CA"),
        "{err}"
    );
}

/// A statement nobody can read is refused, never read as absent (A-2): an
/// unknown profile name, and a launch extension that does not parse.
#[tokio::test]
async fn unreadable_launch_statements_are_refused() {
    let ca = SelfSignedCa::new(TD).unwrap();
    let unknown = raw_leaf(
        &ca,
        "unknown-profile",
        &[
            (oid::OID_NUCLEUS_ATTESTATION_TUPLE, measured().to_der()),
            (
                oid::OID_NUCLEUS_ISOLATION_PROFILE_TUPLE,
                vec![
                    0x0c, 0x09, b'e', b'v', b'a', b'l', b'-', b'c', b'e', b'l', b'k',
                ],
            ),
        ],
    );
    let err = admit(&unknown, &ca).expect_err("an unknown profile");
    assert!(
        err.to_string().contains("unreadable isolation-profile"),
        "{err}"
    );

    let garbled = raw_leaf(
        &ca,
        "garbled-launch",
        &[(
            oid::OID_NUCLEUS_ATTESTATION_TUPLE,
            vec![0x30, 0x03, 0x02, 0x01],
        )],
    );
    let err = admit(&garbled, &ca).expect_err("a launch nobody can read");
    assert!(
        err.to_string().contains("unreadable launch-attestation"),
        "{err}"
    );

    let standard_without_launch = raw_leaf(
        &ca,
        "standard-no-launch",
        &[(
            oid::OID_NUCLEUS_ISOLATION_PROFILE_TUPLE,
            SvidProfile::Standard.extension_value(),
        )],
    );
    let err = admit(&standard_without_launch, &ca).expect_err("a profile with no launch");
    assert!(err.to_string().contains("no measured launch"), "{err}");
}

/// Run one handshake against an acceptor `TlsServerConfig` builds over `ca`'s
/// bundle, and return what the SERVER's accept said.
async fn handshake(ca: &SelfSignedCa, client: WorkloadCertificate) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let server_id = Identity::new(TD, "system", "node");
    let server = plain_leaf(ca, &server_id).await;
    let acceptor = TlsServerConfig::new(server, ca.trust_bundle().clone())
        .build_acceptor()
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serve = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await?;
        tls.write_all(b"ok").await?;
        tls.shutdown().await
    });
    let connector = TlsClientConfig::new(client, ca.trust_bundle().clone())
        .with_spiffe_trust_domain(TD)
        .build_connector()
        .unwrap();
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from(TD.to_string()).unwrap();
    // The client's own result is not the verdict: under TLS 1.3 it finishes
    // before the server has judged its certificate.
    if let Ok(mut tls) = connector.connect(name, tcp).await {
        let mut buf = Vec::new();
        let _ = tls.read_to_end(&mut buf).await;
    }
    serve.await.unwrap()
}

/// ADR 0016 S4's falsifier: an eval-cell SVID with no launch completes a
/// handshake on `main`, whose acceptor checked the chain alone. It must fail
/// the handshake, and the real eval-cell launch beside it must complete one.
#[tokio::test]
async fn an_eval_cell_svid_with_no_launch_fails_the_handshake() {
    let ca = SelfSignedCa::new(TD).unwrap();

    let refused = handshake(&ca, eval_cell_without_launch(&ca))
        .await
        .expect_err("an eval cell with no launch is refused at the handshake");
    assert!(
        refused
            .to_string()
            .contains("eval-cell SVID that carries no launch"),
        "{refused}"
    );

    handshake(&ca, measured_leaf(&ca, "eval", SvidProfile::EvalCell).await)
        .await
        .expect("an eval cell whose launch verifies completes the handshake");
    handshake(&ca, measured_leaf(&ca, "std", SvidProfile::Standard).await)
        .await
        .expect("a standard launch completes the handshake");
    handshake(
        &ca,
        plain_leaf(&ca, &Identity::new(TD, "system", "cli")).await,
    )
    .await
    .expect("a leaf that states no launch completes it, as before");
}
