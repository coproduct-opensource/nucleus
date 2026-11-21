//! `pod_ca`: what the minted certificate says, read back with the proxy's own
//! parser (`PodCa::from_bundle`), so the node's and the proxy's views of one
//! CA cannot drift (ADR 0007 G-1).

use super::*;
use nucleus_egress_proxy::link::link_name;
use nucleus_egress_proxy::tls::PodCa;
use x509_parser::extensions::GeneralName;

const NOW: u64 = 1_800_000_000;
const POD: Uuid = Uuid::from_u128(0x1234);

fn hosts(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| (*s).to_string()).collect()
}

/// The permitted DNS subtrees, read from the certificate itself.
fn constraints_of(der: &[u8]) -> Vec<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).unwrap();
    let nc = cert
        .name_constraints()
        .unwrap()
        .expect("a CA without constraints");
    assert!(
        nc.value
            .excluded_subtrees
            .as_ref()
            .is_none_or(|e| e.is_empty()),
        "no excluded subtrees are minted"
    );
    nc.value
        .permitted_subtrees
        .iter()
        .flatten()
        .map(|s| match s.base {
            GeneralName::DNSName(n) => n.to_string(),
            ref other => panic!("a non-DNS permitted subtree: {other:?}"),
        })
        .collect()
}

#[test]
fn constraints_are_exactly_the_https_hosts_and_the_link_subtree() {
    let ca = MintedCa::mint(POD, &hosts(&["api.example", "Docs.Example"]), NOW, 300).unwrap();
    assert_eq!(
        constraints_of(ca.certificate_der()),
        vec!["api.example", "docs.example", LINK_SUBTREE]
    );
    assert_eq!(ca.permitted(), constraints_of(ca.certificate_der()));
}

#[test]
fn no_https_hosts_still_constrains_to_the_link_namespace() {
    let ca = MintedCa::mint(POD, &[], NOW, 300).unwrap();
    assert_eq!(constraints_of(ca.certificate_der()), vec![LINK_SUBTREE]);
}

#[test]
fn a_host_that_is_not_a_dns_name_is_refused() {
    for bad in [
        "*.example",
        "10.0.0.1:443",
        "",
        "a..b",
        "-x.example",
        "x_y.example",
    ] {
        assert!(
            matches!(
                MintedCa::mint(POD, &hosts(&[bad]), NOW, 300),
                Err(MintError::BadName(_))
            ),
            "{bad:?} must not become a constraint"
        );
    }
}

#[test]
fn not_after_is_no_later_than_the_pod_deadline() {
    let ca = MintedCa::mint(POD, &[], NOW, 300).unwrap();
    let (_, cert) = x509_parser::parse_x509_certificate(ca.certificate_der()).unwrap();
    let not_after = u64::try_from(cert.validity().not_after.timestamp()).unwrap();
    assert!(
        not_after <= NOW + 300,
        "{not_after} > deadline {}",
        NOW + 300
    );
    assert_eq!(ca.not_after(), NOW + 300);
    assert!(
        cert.is_ca(),
        "the pod CA must be a CA, or no client accepts its leaves"
    );
}

#[test]
fn a_deadline_past_the_clock_is_refused() {
    assert_eq!(
        MintedCa::mint(POD, &[], u64::MAX, 1).unwrap_err(),
        MintError::Deadline
    );
}

#[test]
fn link_names_live_under_the_link_subtree() {
    let n = link_name(7);
    assert!(n.ends_with(&format!(".{LINK_SUBTREE}")));
    assert!(n.ends_with(".invalid"), "never a publicly resolvable name");
}

/// The handover writes exactly the bundle the proxy parses, and the proxy reads
/// back the same constraints and deadline the node minted.
#[tokio::test]
async fn the_handover_is_the_bundle_the_proxy_parses() {
    let ca = MintedCa::mint(POD, &hosts(&["api.example"]), NOW, 300).unwrap();
    let cert = ca.certificate_der().to_vec();
    let mut channel: Vec<u8> = Vec::new();
    ca.hand_over(&mut channel).await.unwrap();
    let parsed = PodCa::from_bundle(&channel).unwrap();
    assert_eq!(
        parsed.permitted(),
        &["api.example".to_string(), LINK_SUBTREE.to_string()]
    );
    assert_eq!(parsed.not_after(), NOW + 300);
    assert!(channel.windows(cert.len()).any(|w| w == cert.as_slice()));
}

/// The certificate is the only thing the guest-facing form carries: the PEM
/// decodes to the certificate DER and nothing else, and no rendering of the
/// CA a guest or a log could see contains the key.
#[tokio::test]
async fn the_guest_sees_the_certificate_and_never_the_key() {
    let ca = MintedCa::mint(POD, &hosts(&["api.example"]), NOW, 300).unwrap();
    let key = ca.key_der.to_vec();
    let pem = ca.certificate_pem();
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    use base64::Engine as _;
    let der = base64::engine::general_purpose::STANDARD
        .decode(body)
        .unwrap();
    assert_eq!(der, ca.certificate_der());
    let debug = format!("{ca:?}");
    for rendering in [pem.as_bytes(), debug.as_bytes(), ca.certificate_der()] {
        assert!(
            !rendering.windows(key.len()).any(|w| w == key.as_slice()),
            "the CA key appears in a guest-facing or logged rendering"
        );
    }
    // The bundle is the one form that carries the key, and it only exists
    // inside `hand_over`.
    let mut channel: Vec<u8> = Vec::new();
    ca.hand_over(&mut channel).await.unwrap();
    assert!(channel.windows(key.len()).any(|w| w == key.as_slice()));
}
