use super::*;
use nucleus_identity::ca::MeasuredClaims;
use nucleus_identity::{CaClient, CsrOptions, Identity, LaunchAttestation, SelfSignedCa};
use nucleus_node_evidence::{Expect, REFERENCE_PROFILE, ReferenceValues, evidence_digest};
use std::io::Write;
use std::time::Duration;

/// Mint a real leaf cert via the shipping SelfSignedCa, optionally attested.
async fn mint(ca: &SelfSignedCa, attested: bool) -> (tempfile::NamedTempFile, LaunchAttestation) {
    let identity = Identity::for_pod("test.local", "pod-1");
    let cs = CsrOptions::new(identity.to_spiffe_uri())
        .generate()
        .unwrap();
    let att = LaunchAttestation::from_hashes([1u8; 32], [2u8; 32], [3u8; 32]);
    let cert = if attested {
        ca.sign_attested_csr(
            cs.csr(),
            cs.private_key(),
            &identity,
            Duration::from_secs(3600),
            &att,
        )
        .await
        .unwrap()
    } else {
        ca.sign_csr(
            cs.csr(),
            cs.private_key(),
            &identity,
            Duration::from_secs(3600),
        )
        .await
        .unwrap()
    };
    (file(cert.chain_pem().as_bytes()), att)
}

fn file(bytes: &[u8]) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(bytes).unwrap();
    f
}

/// `ca`'s roots, as the PEM file an operator hands the CLI.
fn bundle(ca: &SelfSignedCa) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    for root in ca.trust_bundle().roots() {
        f.write_all(root.to_pem().as_bytes()).unwrap();
    }
    f
}

/// No TPM inputs: the CA-only verifier, as before S8.
fn no_tpm() -> TpmRootArgs {
    TpmRootArgs {
        launch_quote: None,
        node_reference: None,
        executor_ed25519: None,
        federation: "not-federated".into(),
        ak_trust_root: Vec::new(),
        operator_pin: Vec::new(),
        allow_software_tpm_pin: Vec::new(),
        require_tpm_root: false,
    }
}

fn args(
    f: &tempfile::NamedTempFile,
    b: &tempfile::NamedTempFile,
    k: &[u8; 32],
    r: &[u8; 32],
    c: &[u8; 32],
) -> VerifyAttestationArgs {
    VerifyAttestationArgs {
        cert: f.path().to_path_buf(),
        trust_bundle: b.path().to_path_buf(),
        expect_kernel: vec![hex::encode(k)],
        expect_rootfs: vec![hex::encode(r)],
        expect_config: vec![hex::encode(c)],
        require_attestation: true,
        tpm: no_tpm(),
    }
}

// The CLI production entrypoint verifies a correct attested cert, reds on
// measurement drift, and fails closed on an absent extension (C9 Inc 1).
#[tokio::test]
async fn cli_verifies_attested_and_reds_on_drift_and_absent() {
    let ca = SelfSignedCa::new("test.local").unwrap();
    let b = bundle(&ca);
    let (f, att) = mint(&ca, true).await;

    // Positive control — correct measurement verifies (non-vacuous).
    assert!(
        execute(args(
            &f,
            &b,
            att.kernel_hash(),
            att.rootfs_hash(),
            att.config_hash()
        ))
        .is_ok()
    );

    // Drift — one wrong expected hash reds the CLI verdict.
    let mut wrong = *att.kernel_hash();
    wrong[0] ^= 0x01;
    assert!(execute(args(&f, &b, &wrong, att.rootfs_hash(), att.config_hash())).is_err());

    // Absent — a plain cert with require_attestation fails closed.
    let (plain, _) = mint(&ca, false).await;
    assert!(
        execute(args(
            &plain,
            &b,
            att.kernel_hash(),
            att.rootfs_hash(),
            att.config_hash()
        ))
        .is_err()
    );
}

/// The issuer tooth through the CLI (ADR 0016 S2): the same node-issued leaf
/// is refused against a bundle that did not issue it.
#[tokio::test]
async fn cli_refuses_a_leaf_the_named_bundle_did_not_issue() {
    let ca = SelfSignedCa::new("test.local").unwrap();
    let (f, att) = mint(&ca, true).await;
    let stranger = bundle(&SelfSignedCa::new("test.local").unwrap());
    let err = execute(args(
        &f,
        &stranger,
        att.kernel_hash(),
        att.rootfs_hash(),
        att.config_hash(),
    ))
    .expect_err("a leaf from another CA");
    assert!(
        format!("{err:#}").contains("not issued by a trusted CA"),
        "{err:#}"
    );
}

/// ADR 0016 S2's falsifier: a self-signed `rcgen` leaf carrying the launch
/// extension (OID `.1.1`) and the exact measurement the operator expects.
/// Before #3352 the CLI read the extension and passed it. It must be refused
/// by the issuer tooth, with the node's real bundle present, so the refusal is
/// the chain and not a missing or unreadable file.
#[tokio::test]
async fn cli_refuses_a_self_signed_leaf_carrying_the_launch_extension() {
    let ca = SelfSignedCa::new("test.local").unwrap();
    let b = bundle(&ca);
    let att = LaunchAttestation::from_hashes([1u8; 32], [2u8; 32], [3u8; 32]);

    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.subject_alt_names = vec![rcgen::SanType::URI(
        rcgen::string::Ia5String::try_from(
            Identity::for_pod("test.local", "pod-1").to_spiffe_uri(),
        )
        .unwrap(),
    )];
    params.custom_extensions = vec![rcgen::CustomExtension::from_oid_content(
        nucleus_identity::oid::OID_NUCLEUS_ATTESTATION_TUPLE,
        att.to_der(),
    )];
    let forged = params
        .self_signed(&rcgen::KeyPair::generate().unwrap())
        .unwrap()
        .pem();
    let f = file(forged.as_bytes());

    // The forgery really carries the claim the operator expects: the
    // extension alone, read the way the pre-#3352 CLI read it, matches.
    let der = pem::parse(&forged).unwrap();
    let lifted = nucleus_identity::extract_launch_attestation(der.contents())
        .expect("the forgery carries a launch claim");
    AttestationRequirements::exact(*att.kernel_hash(), *att.rootfs_hash(), *att.config_hash())
        .verify(&lifted)
        .expect("the very measurement the operator expects");

    for require_attestation in [true, false] {
        let mut a = args(
            &f,
            &b,
            att.kernel_hash(),
            att.rootfs_hash(),
            att.config_hash(),
        );
        a.require_attestation = require_attestation;
        let err = execute(a).expect_err("a self-signed launch claim");
        assert!(
            format!("{err:#}").contains("not issued by a trusted CA"),
            "require_attestation={require_attestation}: {err:#}"
        );
    }
}

#[test]
fn rejects_malformed_hex_measurement() {
    assert!(parse_hash("not-hex").is_err());
    assert!(parse_hash("ab").is_err()); // too short
}

// ---- ADR 0016 S8: the TPM root through the CLI --------------------------------
//
// The quote is the swtpm fixture S3 checked in
// (`nucleus-identity/tests/fixtures/launch-quote/`, capture recipe in
// `nucleus-identity/src/launch_quote_tests.rs`): taken over the fixture key's
// SPKI and kernel 0x11…, rootfs 0x22…, config 0x33…, bound to executor key
// 0x5e…, not federated. Each test signs its own leaf over that key, so the
// CA is one the test controls and a swapped key is a real swap.

const LEAF_KEY: &str =
    include_str!("../../nucleus-identity/tests/fixtures/launch-quote/leaf-key.pem");
const QUOTE: &[u8] =
    include_bytes!("../../nucleus-identity/tests/fixtures/launch-quote/quote.json");
/// SHA-256 of the swtpm AK's SubjectPublicKeyInfo.
const AK_PIN: &str = "c973a42e47c26d950b76f3930f8abcdb5f3915ae2c1d1df767f776f7d1025b9a";
const SOURCE: &str = "swtpm-fixture";

fn quoted() -> LaunchAttestation {
    LaunchAttestation::from_hashes([0x11; 32], [0x22; 32], [0x33; 32])
}

fn quoted_identity() -> Identity {
    Identity::for_pod("test.local", "launch-quoted")
}

/// A leaf `ca` signs over `key_pem`, stating the quoted measurement and
/// naming `quote`.
async fn quoted_leaf(
    ca: &SelfSignedCa,
    key_pem: &str,
    quote: Option<&[u8; 32]>,
) -> tempfile::NamedTempFile {
    let key = rcgen::KeyPair::from_pem(key_pem).unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.subject_alt_names = vec![rcgen::SanType::URI(
        rcgen::string::Ia5String::try_from(quoted_identity().to_spiffe_uri()).unwrap(),
    )];
    let csr = params.serialize_request(&key).unwrap().pem().unwrap();
    let cert = ca
        .sign_measured_csr(
            &csr,
            key_pem,
            &quoted_identity(),
            Duration::from_secs(3600),
            &MeasuredClaims {
                attestation: &quoted(),
                mediator_key_sha256: None,
                launch_quote_sha256: quote,
                isolation_profile: nucleus_identity::SvidProfile::Standard,
            },
        )
        .await
        .unwrap();
    file(cert.chain_pem().as_bytes())
}

/// The swtpm has no firmware and no IMA, so the reference checks no PCR.
fn reference_file() -> tempfile::NamedTempFile {
    fn none<T>() -> Expect<T> {
        Expect::NotChecked("software TPM: no firmware, no IMA".into())
    }
    let reference = ReferenceManifest {
        profile: REFERENCE_PROFILE.into(),
        tag_id: "swtpm-fixture".into(),
        reference_values: ReferenceValues {
            pcrs: Default::default(),
            secure_boot: none(),
            efi_applications: none(),
            boot_files: none(),
            kernel_cmdline: none(),
            ima: none(),
        },
    };
    file(&serde_json::to_vec(&reference).unwrap())
}

/// The CLI inputs for the fixture: the leaf, its bundle, the quoted
/// measurement, and (with `quote`) the quote plus the node reference, executor
/// key and software-TPM pin.
struct Fixture {
    leaf: tempfile::NamedTempFile,
    bundle: tempfile::NamedTempFile,
    quote: tempfile::NamedTempFile,
    reference: tempfile::NamedTempFile,
}

impl Fixture {
    fn args(&self, with_quote: bool) -> VerifyAttestationArgs {
        let m = quoted();
        let mut a = args(
            &self.leaf,
            &self.bundle,
            m.kernel_hash(),
            m.rootfs_hash(),
            m.config_hash(),
        );
        if with_quote {
            a.tpm = TpmRootArgs {
                launch_quote: Some(self.quote.path().to_path_buf()),
                node_reference: Some(self.reference.path().to_path_buf()),
                executor_ed25519: Some(hex::encode([0x5e; 32])),
                federation: "not-federated".into(),
                ak_trust_root: Vec::new(),
                operator_pin: Vec::new(),
                allow_software_tpm_pin: vec![format!("{SOURCE}={AK_PIN}")],
                require_tpm_root: false,
            };
        }
        a
    }
}

async fn fixture(key_pem: &str, quote_document: &[u8]) -> Fixture {
    let ca = SelfSignedCa::new("test.local").unwrap();
    Fixture {
        leaf: quoted_leaf(&ca, key_pem, Some(&evidence_digest(QUOTE))).await,
        bundle: bundle(&ca),
        quote: file(quote_document),
        reference: reference_file(),
    }
}

/// Non-vacuous: the quote the swtpm took over this leaf's key and measurement
/// roots it, and the CLI reports the TPM root by the digest the leaf names.
#[tokio::test]
async fn a_tpm_rooted_launch_quote_verifies_as_tpm() {
    let fx = fixture(LEAF_KEY, QUOTE).await;
    let Verdict::Launch { root, .. } = verify(&fx.args(true)).expect("the quoted launch") else {
        panic!("a measured leaf is a launch");
    };
    let Root::Tpm(appraised) = root else {
        panic!("a quote that appraised Attested roots the launch in the TPM, got {root:?}");
    };
    assert_eq!(appraised.quote_sha256(), &evidence_digest(QUOTE));
    assert_eq!(
        appraised.appraisal().anchor(),
        &nucleus_node_evidence::AkAnchor::SoftwareTpm {
            source: SOURCE.into()
        }
    );

    let mut required = fx.args(true);
    required.tpm.require_tpm_root = true;
    execute(required).expect("--require-tpm-root holds for a TPM-rooted launch");
}

/// A certificate swap: the same CA, the same measurement, the same `.1.7`,
/// another key. The CA-only verdict cannot see it; the quote refuses it.
#[tokio::test]
async fn a_launch_quote_over_another_spki_is_refused() {
    let other = rcgen::KeyPair::generate().unwrap().serialize_pem();
    let fx = fixture(&other, QUOTE).await;
    verify(&fx.args(false)).expect("the CA signed it: the CA-only root cannot see the swap");
    let err = verify(&fx.args(true)).expect_err("a quote over another key");
    assert!(
        format!("{err:#}").contains("not taken over this leaf's key and measurement"),
        "{err:#}"
    );
}

/// The runbook's falsifier (ADR 0016 S8): the quote document altered by one
/// byte is not the document the leaf names, and is refused.
#[tokio::test]
async fn an_altered_launch_quote_document_is_refused() {
    let mut altered = QUOTE.to_vec();
    let at = altered.iter().position(|b| *b == b'{').unwrap();
    altered.insert(at + 1, b' ');
    let fx = fixture(LEAF_KEY, &altered).await;
    let err = verify(&fx.args(true)).expect_err("a document the leaf does not name");
    assert!(format!("{err:#}").contains("but the leaf names"), "{err:#}");
}

/// Could-not-check is never verified-as-TPM: a leaf that names a quote, given
/// without one, is reported CA-only with the digest to fetch; a leaf naming no
/// quote is reported CA-only for that reason. `--require-tpm-root` refuses both.
#[tokio::test]
async fn a_launch_without_its_quote_is_reported_ca_only_not_tpm() {
    let fx = fixture(LEAF_KEY, QUOTE).await;
    let Verdict::Launch { root, .. } = verify(&fx.args(false)).expect("CA-only verifies") else {
        panic!("a measured leaf is a launch");
    };
    let Root::NodeCaOnly(why) = root else {
        panic!("an unchecked quote is not a TPM root, got {root:?}");
    };
    assert_eq!(
        why,
        NotTpm::QuoteNotChecked {
            named: evidence_digest(QUOTE)
        }
    );

    let ca = SelfSignedCa::new("test.local").unwrap();
    let unquoted = Fixture {
        leaf: quoted_leaf(&ca, LEAF_KEY, None).await,
        bundle: bundle(&ca),
        quote: file(QUOTE),
        reference: reference_file(),
    };
    let Verdict::Launch { root, .. } = verify(&unquoted.args(false)).expect("CA-only verifies")
    else {
        panic!("a measured leaf is a launch");
    };
    assert!(
        matches!(root, Root::NodeCaOnly(NotTpm::NoQuoteNamed)),
        "{root:?}"
    );
    // A quote supplied for a leaf that names none roots nothing.
    let err = verify(&unquoted.args(true)).expect_err("the leaf names no quote");
    assert!(
        format!("{err:#}").contains("names no launch quote"),
        "{err:#}"
    );

    for f in [&fx, &unquoted] {
        let mut required = f.args(false);
        required.tpm.require_tpm_root = true;
        let err = verify(&required).expect_err("--require-tpm-root without a TPM root");
        assert!(format!("{err:#}").contains("--require-tpm-root"), "{err:#}");
    }
}
