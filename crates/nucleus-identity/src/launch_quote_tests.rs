//! The launch quote's falsifiers (ADR 0016 S3), against a quote a software TPM
//! took.
//!
//! # The fixture (`tests/fixtures/launch-quote/`)
//!
//! Captured once with swtpm 0.7 on the agent builder, 2026-10-13:
//!
//! ```text
//! openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out leaf-key.pem
//! openssl pkey -in leaf-key.pem -pubout -outform DER -out spki.der
//! # the nonce, by hand, from the D2 encoding (and recomputed by the test below):
//! { printf 'nucleus-launch-v1'; cat spki.der;
//!   head -c 32 /dev/zero | tr '\0' '\021'; head -c 32 /dev/zero | tr '\0' '\042';
//!   head -c 32 /dev/zero | tr '\0' '\063'; } | sha256sum
//! swtpm socket --tpm2 --tpmstate dir=$D --server type=tcp,port=2321 \
//!   --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear &
//! cargo run -p nucleus-node-evidence --features attester --example swtpm_attest -- \
//!   127.0.0.1:2321 $(printf '5e%.0s' $(seq 32)) nonce:$NONCE software-tpm:swtpm-fixture \
//!   > quote.json   # stderr: ak_spki_sha256=<AK_PIN below>
//! ```
//!
//! The measurement is kernel `0x11…`, rootfs `0x22…`, config `0x33…`; the
//! executor key `0x5e…`, not federated. The fixture holds no CA: each test
//! signs its own leaf over the fixture key, so a leaf the quote names is
//! signed by a CA the test controls and the swap below is a real one.

use super::*;
use crate::ca::{CaClient, MeasuredClaims};
use crate::{Identity, SelfSignedCa, VerifiedLaunch};
use nucleus_node_evidence::{
    AkAnchor, ExecutorKey, Expect, Federation, Freshness, OperatorPin, REFERENCE_PROFILE,
    ReferenceValues,
};
use std::time::Duration;

const LEAF_KEY: &str = include_str!("../tests/fixtures/launch-quote/leaf-key.pem");
const QUOTE: &[u8] = include_bytes!("../tests/fixtures/launch-quote/quote.json");
/// SHA-256 of the swtpm AK's SubjectPublicKeyInfo, from `swtpm_attest`'s stderr.
const AK_PIN: &str = "c973a42e47c26d950b76f3930f8abcdb5f3915ae2c1d1df767f776f7d1025b9a";
const SOURCE: &str = "swtpm-fixture";
const NOW: i64 = 1_791_000_000;

fn measured() -> LaunchAttestation {
    LaunchAttestation::from_hashes([0x11; 32], [0x22; 32], [0x33; 32])
}

fn binding() -> KeyBinding {
    KeyBinding {
        executor_key: ExecutorKey::Ed25519([0x5e; 32]),
        federation: Federation::NotFederated,
    }
}

fn reference(pcrs: std::collections::BTreeMap<u8, String>) -> ReferenceManifest {
    fn none<T>() -> Expect<T> {
        Expect::NotChecked("software TPM: no firmware, no IMA".into())
    }
    ReferenceManifest {
        profile: REFERENCE_PROFILE.into(),
        tag_id: "swtpm-fixture".into(),
        reference_values: ReferenceValues {
            pcrs,
            secure_boot: none(),
            efi_applications: none(),
            boot_files: none(),
            kernel_cmdline: none(),
            ima: none(),
        },
    }
}

fn pinned() -> AnchorPolicy {
    AnchorPolicy {
        trust_roots: Vec::new(),
        operator_pins: Vec::new(),
        software_tpm_pins: vec![OperatorPin {
            source: SOURCE.into(),
            ak_spki_sha256: AK_PIN.into(),
        }],
    }
}

/// Run `f` with the relying party's inputs for the fixture.
fn with_policy<T>(f: impl FnOnce(&LaunchQuotePolicy<'_>) -> T) -> T {
    let b = binding();
    let r = reference(Default::default());
    let a = pinned();
    f(&LaunchQuotePolicy {
        expected_binding: &b,
        reference: &r,
        anchors: &a,
        now: NOW,
    })
}

fn identity() -> Identity {
    Identity::for_pod("test.local", "launch-quoted")
}

/// A CSR over `key_pem`, as the secret manager would make for that key.
fn csr_for(key_pem: &str) -> String {
    let key = rcgen::KeyPair::from_pem(key_pem).unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.subject_alt_names = vec![rcgen::SanType::URI(
        rcgen::string::Ia5String::try_from(identity().to_spiffe_uri()).unwrap(),
    )];
    params.serialize_request(&key).unwrap().pem().unwrap()
}

/// A leaf `ca` signs over `key_pem`, stating `launch` and naming `quote`.
async fn leaf(
    ca: &SelfSignedCa,
    key_pem: &str,
    launch: &LaunchAttestation,
    quote: Option<&Hash256>,
) -> Vec<u8> {
    ca.sign_measured_csr(
        &csr_for(key_pem),
        key_pem,
        &identity(),
        Duration::from_secs(3600),
        &MeasuredClaims {
            attestation: launch,
            mediator_key_sha256: None,
            launch_quote_sha256: quote,
            isolation_profile: crate::SvidProfile::Standard,
        },
    )
    .await
    .unwrap()
    .leaf()
    .der()
    .to_vec()
}

fn fixture_digest() -> Hash256 {
    evidence_digest(QUOTE)
}

/// The D2 encoding, pinned. Computed with `sha256sum` over the bytes the
/// module docs list, independently of this crate.
#[test]
fn the_launch_nonce_encoding_is_pinned() {
    let n = launch_nonce(b"spki", &measured());
    assert_eq!(format_hash(&n), GOLDEN);
}

/// `printf 'nucleus-launch-v1spki'` then 32 × 0x11, 32 × 0x22, 32 × 0x33, through `sha256sum`.
const GOLDEN: &str = "a72f65a53bfad45fed894cd930c491b3c52759bb0135a9c1bb44caa2a1b65c60";

/// Non-vacuous: the quote the swtpm took roots the leaf it was taken for, and
/// it was taken over exactly the nonce this crate computes for that leaf.
#[tokio::test]
async fn the_fixture_quote_roots_the_leaf_it_was_taken_for() {
    let ca = SelfSignedCa::new("test.local").unwrap();
    let leaf = leaf(&ca, LEAF_KEY, &measured(), Some(&fixture_digest())).await;

    let evidence: NodeEvidence = serde_json::from_slice(QUOTE).unwrap();
    let expected = launch_nonce(&leaf_spki(&leaf).unwrap(), &measured());
    assert_eq!(
        evidence.freshness,
        Freshness::Challenge {
            eat_nonce: Nonce::new(expected.to_vec()).unwrap()
        },
        "the fixture was taken over the nonce of this leaf's key and measurement"
    );

    let v = with_policy(|p| VerifiedLaunch::verify_tpm(&leaf, ca.trust_bundle(), QUOTE, p))
        .expect("the quoted launch verifies");
    let LaunchRoot::Tpm(appraised) = v.root() else {
        panic!("verify_tpm roots the launch in the TPM, got {:?}", v.root());
    };
    assert_eq!(appraised.quote_sha256(), &fixture_digest());
    assert_eq!(appraised.appraisal().tier(), &Tier::Attested);
    assert_eq!(
        appraised.appraisal().anchor(),
        &AkAnchor::SoftwareTpm {
            source: SOURCE.into()
        }
    );
    assert_eq!(v.spiffe_id(), identity().to_spiffe_uri());

    // The CA-only decider says only what the CA said.
    let ca_only = VerifiedLaunch::verify(&leaf, ca.trust_bundle()).unwrap();
    assert!(matches!(ca_only.root(), LaunchRoot::NodeCa));
}

/// A quote over a different SPKI (certificate swapped): the same CA, the same
/// measurement, the same `.1.7`, another key. The CA alone cannot tell it from
/// the real leaf; the quote can.
#[tokio::test]
async fn a_quote_over_a_different_spki_is_refused() {
    let ca = SelfSignedCa::new("test.local").unwrap();
    let other_key = rcgen::KeyPair::generate().unwrap().serialize_pem();
    let swapped = leaf(&ca, &other_key, &measured(), Some(&fixture_digest())).await;

    VerifiedLaunch::verify(&swapped, ca.trust_bundle())
        .expect("the CA signed it: the CA-only root cannot see the swap");
    let err = with_policy(|p| VerifiedLaunch::verify_tpm(&swapped, ca.trust_bundle(), QUOTE, p))
        .expect_err("a quote over another key does not root this leaf");
    assert!(
        err.to_string()
            .contains("not taken over this leaf's key and measurement"),
        "{err}"
    );
}

/// One byte of measurement drift, in each of the three measurements, is refused.
#[tokio::test]
async fn one_byte_of_measurement_drift_is_refused() {
    let ca = SelfSignedCa::new("test.local").unwrap();
    let mut drifts = Vec::new();
    for which in 0..3 {
        let mut m = [[0x11u8; 32], [0x22; 32], [0x33; 32]];
        m[which][31] ^= 0x01;
        drifts.push(LaunchAttestation::from_hashes(m[0], m[1], m[2]));
    }
    for drifted in drifts {
        let leaf = leaf(&ca, LEAF_KEY, &drifted, Some(&fixture_digest())).await;
        let err = with_policy(|p| VerifiedLaunch::verify_tpm(&leaf, ca.trust_bundle(), QUOTE, p))
            .expect_err("a drifted measurement is not the launch the TPM quoted");
        assert!(
            err.to_string()
                .contains("not taken over this leaf's key and measurement"),
            "{}: {err}",
            drifted.to_hex_summary()
        );
    }
}

/// The document must be the one the leaf names: a leaf naming another digest,
/// and the named document with one byte changed, are both refused.
#[tokio::test]
async fn a_document_other_than_the_one_the_leaf_names_is_refused() {
    let ca = SelfSignedCa::new("test.local").unwrap();
    let mut other = fixture_digest();
    other[0] ^= 0x01;
    let names_other = leaf(&ca, LEAF_KEY, &measured(), Some(&other)).await;
    let err =
        with_policy(|p| VerifiedLaunch::verify_tpm(&names_other, ca.trust_bundle(), QUOTE, p))
            .expect_err("the leaf names another document");
    assert!(err.to_string().contains("but the leaf names"), "{err}");

    let real = leaf(&ca, LEAF_KEY, &measured(), Some(&fixture_digest())).await;
    let mut altered = QUOTE.to_vec();
    let at = altered.iter().position(|b| *b == b'{').unwrap();
    altered.insert(at + 1, b' ');
    let err = with_policy(|p| VerifiedLaunch::verify_tpm(&real, ca.trust_bundle(), &altered, p))
        .expect_err("a document that is not the named one");
    assert!(err.to_string().contains("but the leaf names"), "{err}");
}

/// A leaf that names no quote has no TPM root, whatever document is offered.
#[tokio::test]
async fn a_leaf_naming_no_quote_has_no_tpm_root() {
    let ca = SelfSignedCa::new("test.local").unwrap();
    let unquoted = leaf(&ca, LEAF_KEY, &measured(), None).await;
    let err = with_policy(|p| VerifiedLaunch::verify_tpm(&unquoted, ca.trust_bundle(), QUOTE, p))
        .expect_err("no launch quote is named");
    assert!(err.to_string().contains("names no launch quote"), "{err}");
}

/// Only `Attested` roots a launch: the same quote with its AK unpinned
/// (`unattested`), or against a reference its boot diverges from (`contested`).
#[tokio::test]
async fn a_quote_that_does_not_appraise_attested_roots_nothing() {
    let ca = SelfSignedCa::new("test.local").unwrap();
    let leaf = leaf(&ca, LEAF_KEY, &measured(), Some(&fixture_digest())).await;
    let b = binding();

    let r = reference(Default::default());
    let unpinned = AnchorPolicy {
        trust_roots: Vec::new(),
        operator_pins: Vec::new(),
        software_tpm_pins: Vec::new(),
    };
    let err = VerifiedLaunch::verify_tpm(
        &leaf,
        ca.trust_bundle(),
        QUOTE,
        &LaunchQuotePolicy {
            expected_binding: &b,
            reference: &r,
            anchors: &unpinned,
            now: NOW,
        },
    )
    .expect_err("an unanchored AK");
    assert!(err.to_string().contains("`unattested`"), "{err}");

    let diverges = reference([(0u8, "ff".repeat(32))].into_iter().collect());
    let a = pinned();
    let err = VerifiedLaunch::verify_tpm(
        &leaf,
        ca.trust_bundle(),
        QUOTE,
        &LaunchQuotePolicy {
            expected_binding: &b,
            reference: &diverges,
            anchors: &a,
            now: NOW,
        },
    )
    .expect_err("a boot the reference does not allow");
    assert!(err.to_string().contains("`contested`"), "{err}");
}

/// The quote speaks for the node's keys: a relying party expecting another
/// executor key refuses it.
#[tokio::test]
async fn a_quote_bound_to_another_executor_key_is_refused() {
    let ca = SelfSignedCa::new("test.local").unwrap();
    let leaf = leaf(&ca, LEAF_KEY, &measured(), Some(&fixture_digest())).await;
    let other = KeyBinding {
        executor_key: ExecutorKey::Ed25519([0x5f; 32]),
        federation: Federation::NotFederated,
    };
    let r = reference(Default::default());
    let a = pinned();
    let err = VerifiedLaunch::verify_tpm(
        &leaf,
        ca.trust_bundle(),
        QUOTE,
        &LaunchQuotePolicy {
            expected_binding: &other,
            reference: &r,
            anchors: &a,
            now: NOW,
        },
    )
    .expect_err("another node's executor key");
    assert!(err.to_string().contains("refused"), "{err}");
}

/// A `.1.7` value nobody can read is refused, never read as absent (A-2).
#[test]
fn an_unreadable_launch_quote_extension_is_refused() {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.custom_extensions = vec![rcgen::CustomExtension::from_oid_content(
        oid::OID_NUCLEUS_LAUNCH_QUOTE_TUPLE,
        vec![0x04, 0x02, 0xde, 0xad],
    )];
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    assert!(extract_launch_quote_digest(cert.der()).is_err());

    let digest = [0xab; 32];
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.custom_extensions = vec![rcgen::CustomExtension::from_oid_content(
        oid::OID_NUCLEUS_LAUNCH_QUOTE_TUPLE,
        launch_quote_extension_value(&digest),
    )];
    let cert = params.self_signed(&key).unwrap();
    assert_eq!(
        extract_launch_quote_digest(cert.der()).unwrap(),
        Some(digest)
    );
}

/// A quoter that records what it was asked to quote, as the node's TPM would
/// be asked, and answers with a fixed digest, or fails.
struct Recording {
    asked: std::sync::Mutex<Vec<Hash256>>,
    answer: Option<Hash256>,
}

impl LaunchQuoter for Recording {
    fn quote_launch(&self, nonce: Hash256) -> QuoteFuture<'_> {
        self.asked.lock().unwrap().push(nonce);
        let answer = self.answer;
        Box::pin(
            async move { answer.ok_or_else(|| Error::Internal("the TPM is unavailable".into())) },
        )
    }
}

/// The secret manager quotes the key the leaf it issues carries, names the
/// quote in that leaf, quotes again on every re-issue (a new key), and issues
/// nothing when the quote cannot be taken.
#[tokio::test]
async fn the_secret_manager_quotes_the_key_each_leaf_carries() {
    let ca = Arc::new(SelfSignedCa::new("test.local").unwrap());
    let manager = crate::SecretManager::new(ca, Duration::from_secs(3600));
    let quoter = Arc::new(Recording {
        asked: std::sync::Mutex::new(Vec::new()),
        answer: Some([0x77; 32]),
    });
    let launch = crate::Launch::Measured {
        attestation: measured(),
        mediator_key_sha256: None,
        rooting: LaunchRooting::Tpm(quoter.clone()),
        profile: crate::SvidProfile::Standard,
    };
    let first = manager.issue_for_launch(&identity(), launch).await.unwrap();
    let again = manager.refresh_certificate(&identity()).await.unwrap();
    let asked = quoter.asked.lock().unwrap().clone();
    assert_eq!(asked.len(), 2, "each issue is quoted");
    for (cert, nonce) in [(&first, asked[0]), (&again, asked[1])] {
        let der = cert.leaf().der();
        assert_eq!(
            launch_nonce(&leaf_spki(der).unwrap(), &measured()),
            nonce,
            "the quote is over the key this leaf carries"
        );
        assert_eq!(extract_launch_quote_digest(der).unwrap(), Some([0x77; 32]));
    }
    assert_ne!(asked[0], asked[1], "a re-issue has a new key");

    let failing = crate::Launch::Measured {
        attestation: measured(),
        mediator_key_sha256: None,
        rooting: LaunchRooting::Tpm(Arc::new(Recording {
            asked: std::sync::Mutex::new(Vec::new()),
            answer: None,
        })),
        profile: crate::SvidProfile::Standard,
    };
    let other = Identity::for_pod("test.local", "unquotable");
    let err = manager
        .issue_for_launch(&other, failing)
        .await
        .expect_err("no quote, no certificate");
    assert!(err.to_string().contains("the TPM is unavailable"), "{err}");
}
