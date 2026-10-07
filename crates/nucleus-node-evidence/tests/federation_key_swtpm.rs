//! The TPM-resident federation key against real software TPMs (libtpms via
//! swtpm), checked by the verifier (ADR 0012).
//!
//! Each test starts its own swtpm processes (fresh state, so fresh seeds),
//! which the "blob moved to another TPM" test needs two of. Needs `swtpm` on
//! `PATH` (or `NUCLEUS_SWTPM_BIN`). Ignored by default; an ignored test is
//! reported as ignored, never as a pass.
#![cfg(feature = "attester")]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use base64::Engine as _;
use nucleus_node_evidence::attester::{AkTemplate, Attester, LogSources, default_pcrs};
use nucleus_node_evidence::key_attestation::boot_policy_pcrs;
use nucleus_node_evidence::tpm::AkPublic;
use nucleus_node_evidence::tpm_key::{
    AnyTransport, TpmEndpoint, WrappedKey, create_federation_key, sign_with_federation_key,
};
use nucleus_node_evidence::{
    AkAnchorClaim, AnchorPolicy, AppraisalPolicy, CustodyStatement, ExecutorKey, Expect,
    Federation, FederationKeyAttestation, Freshness, FreshnessExpectation, KEY_ATTESTATION_PROFILE,
    KeyBinding, KeyRefusal, KeyResidency, Nonce, OperatorPin, REFERENCE_PROFILE, ReferenceManifest,
    ReferenceValues, Tier, appraise_federation_keys,
};
use sha2::Digest as _;

const SOURCE: &str = "swtpm-operator";
const KID: &str = "swtpm-federation-key";

/// One swtpm process with its own state directory, killed on drop.
struct Swtpm {
    child: Child,
    dir: PathBuf,
    addr: String,
}

impl Swtpm {
    fn start() -> Self {
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let dir = std::env::temp_dir().join(format!("nucleus-swtpm-{}-{port}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bin = std::env::var("NUCLEUS_SWTPM_BIN").unwrap_or_else(|_| "swtpm".into());
        let child = Command::new(bin)
            .args(["socket", "--tpm2", "--tpmstate"])
            .arg(format!("dir={}", dir.display()))
            .args(["--server"])
            .arg(format!("type=tcp,port={port},bindaddr=127.0.0.1"))
            .args(["--ctrl"])
            .arg(format!(
                "type=tcp,port={},bindaddr=127.0.0.1",
                port.checked_add(1).unwrap()
            ))
            .args(["--flags", "not-need-init,startup-clear"])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("swtpm on PATH (or NUCLEUS_SWTPM_BIN)");
        let addr = format!("127.0.0.1:{port}");
        for _ in 0..100 {
            if std::net::TcpStream::connect(&addr).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        // That probe connection was one client; let swtpm see it close.
        std::thread::sleep(Duration::from_millis(100));
        Self { child, dir, addr }
    }

    fn endpoint(&self) -> TpmEndpoint {
        TpmEndpoint::Socket(self.addr.clone())
    }

    fn tpm(&self) -> nucleus_node_evidence::attester::Tpm<AnyTransport> {
        self.endpoint().connect().unwrap()
    }
}

impl Drop for Swtpm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn digest(msg: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(msg).into()
}

fn verifies(key: &WrappedKey, digest: &[u8; 32], sig: &[u8; 64]) -> bool {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    let (x, y) = key.point();
    let mut sec1 = vec![0x04];
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).unwrap();
    let sig = p256::ecdsa::Signature::from_slice(sig).unwrap();
    vk.verify_prehash(digest, &sig).is_ok()
}

#[test]
#[ignore = "needs swtpm on PATH"]
fn a_federation_key_signs_and_the_signature_verifies() {
    let a = Swtpm::start();
    let mut tpm = a.tpm();
    let key = create_federation_key(&mut tpm, &boot_policy_pcrs()).unwrap();
    assert_eq!(key.policy_pcrs(), &boot_policy_pcrs());
    let now = tpm.pcr_read(&boot_policy_pcrs()).unwrap();
    assert!(key.policy_matches(&now).unwrap());
    let d = digest(b"header.payload");
    let sig = sign_with_federation_key(&mut tpm, &key, &d).unwrap();
    assert!(verifies(&key, &d, &sig), "the TPM's signature verifies");
    assert!(!verifies(&key, &digest(b"header.other"), &sig));
    // The key signs again: every handle and the session were released.
    let again = sign_with_federation_key(&mut tpm, &key, &d).unwrap();
    assert!(verifies(&key, &d, &again));
}

#[test]
#[ignore = "needs swtpm on PATH"]
fn extending_a_policy_pcr_stops_the_key() {
    let a = Swtpm::start();
    let mut tpm = a.tpm();
    let key = create_federation_key(&mut tpm, &boot_policy_pcrs()).unwrap();
    let d = digest(b"header.payload");
    sign_with_federation_key(&mut tpm, &key, &d).unwrap();
    // PCR 8 is the kernel command line: a boot that differs there.
    tpm.pcr_extend(8, &[0x08; 32]).unwrap();
    let err = sign_with_federation_key(&mut tpm, &key, &d).unwrap_err();
    assert!(err.is_policy_failure(), "refused for its policy: {err}");
    let now = tpm.pcr_read(&boot_policy_pcrs()).unwrap();
    assert!(!key.policy_matches(&now).unwrap());
    // A PCR outside the policy moves nothing.
    let b = Swtpm::start();
    let mut tpm = b.tpm();
    let key = create_federation_key(&mut tpm, &boot_policy_pcrs()).unwrap();
    tpm.pcr_extend(16, &[0x16; 32]).unwrap();
    sign_with_federation_key(&mut tpm, &key, &d).unwrap();
}

#[test]
#[ignore = "needs swtpm on PATH"]
fn a_blob_moved_to_another_tpm_does_not_load() {
    let a = Swtpm::start();
    let b = Swtpm::start();
    let key = create_federation_key(&mut a.tpm(), &boot_policy_pcrs()).unwrap();
    let d = digest(b"header.payload");
    // Same PCR values on both (neither has firmware), so only the TPM differs.
    let err = sign_with_federation_key(&mut b.tpm(), &key, &d).unwrap_err();
    assert!(err.is_integrity_failure(), "refused at Load: {err}");
    // And the blob still works where it was made.
    sign_with_federation_key(&mut a.tpm(), &key, &d).unwrap();
}

fn reference() -> ReferenceManifest {
    fn none<T>() -> Expect<T> {
        Expect::NotChecked("software TPM: no firmware".into())
    }
    ReferenceManifest {
        profile: REFERENCE_PROFILE.into(),
        tag_id: "swtpm".into(),
        reference_values: ReferenceValues {
            pcrs: Default::default(),
            secure_boot: none(),
            efi_applications: none(),
            boot_files: none(),
            kernel_cmdline: none(),
            ima: none(),
        },
    }
}

fn no_logs() -> LogSources {
    LogSources {
        boot_event_log: "/nonexistent/boot".into(),
        ima_sha256: "/nonexistent/ima256".into(),
        ima_sha1: "/nonexistent/ima1".into(),
    }
}

fn jwks_for(key: &WrappedKey) -> serde_json::Value {
    let b = |v: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v);
    let (x, y) = key.point();
    serde_json::json!({ "keys": [{
        "kty": "EC", "crv": "P-256", "x": b(&x), "y": b(&y), "kid": KID
    }]})
}

struct Stranger {
    evidence: nucleus_node_evidence::NodeEvidence,
    anchors: AnchorPolicy,
    binding: KeyBinding,
    nonce: Nonce,
}

impl Stranger {
    fn check(
        &self,
        jwks: &serde_json::Value,
        doc: &FederationKeyAttestation,
    ) -> Result<(Tier, Vec<KeyResidency>), KeyRefusal> {
        let r = reference();
        appraise_federation_keys(
            &self.evidence,
            &AppraisalPolicy {
                expected_binding: &self.binding,
                freshness: FreshnessExpectation::Challenge {
                    sent: self.nonce.clone(),
                },
                reference: &r,
                anchors: &self.anchors,
                now: 1_791_000_000,
            },
            jwks,
            doc,
        )
        .map(|(a, v)| (a.tier().clone(), v))
    }
}

/// Quote the boot PCRs (and 0–10, 14) over a nonce with the default AK.
fn attest(attester: &mut Attester<AnyTransport>, nonce_byte: u8) -> Stranger {
    let ak = AkPublic::from_tpm2b_public(&attester.ak_public().unwrap()).unwrap();
    let binding = KeyBinding {
        executor_key: ExecutorKey::Ed25519([0x5e; 32]),
        federation: Federation::JwksSha256([0x1f; 32]),
    };
    let nonce = Nonce::new(vec![nonce_byte; 32]).unwrap();
    let evidence = attester
        .attest(
            &binding,
            Freshness::Challenge {
                eat_nonce: nonce.clone(),
            },
        )
        .unwrap();
    Stranger {
        evidence,
        anchors: AnchorPolicy {
            trust_roots: vec![],
            operator_pins: vec![OperatorPin {
                source: SOURCE.into(),
                ak_spki_sha256: hex::encode(ak.spki_sha256()),
            }],
        },
        binding,
        nonce,
    }
}

fn doc(custody: CustodyStatement) -> FederationKeyAttestation {
    FederationKeyAttestation {
        profile: KEY_ATTESTATION_PROFILE.into(),
        keys: vec![nucleus_node_evidence::AttestedKey {
            kid: KID.into(),
            custody,
        }],
    }
}

#[test]
#[ignore = "needs swtpm on PATH"]
fn the_aks_certification_verifies_and_tampering_is_refused() {
    let a = Swtpm::start();
    let mut attester = Attester::new(
        a.tpm(),
        AkTemplate::DefaultEccP256,
        default_pcrs(),
        no_logs(),
        AkAnchorClaim::OperatorFetched {
            source: SOURCE.into(),
        },
    );
    let key = create_federation_key(attester.tpm(), &boot_policy_pcrs()).unwrap();
    let other = create_federation_key(attester.tpm(), &boot_policy_pcrs()).unwrap();
    let statement = attester.certify_federation_key(&key).unwrap();
    let stranger = attest(&mut attester, 0x77);
    let jwks = jwks_for(&key);

    // Honest: TPM-resident, bound to the quoted boot PCRs, on an Attested quote.
    let (tier, verdicts) = stranger.check(&jwks, &doc(statement.clone())).unwrap();
    assert_eq!(tier, Tier::Attested);
    assert!(
        matches!(&verdicts[..], [KeyResidency::TpmBound { kid, policy_pcrs, .. }]
            if kid == KID && policy_pcrs == &boot_policy_pcrs()),
        "{verdicts:?}"
    );

    let CustodyStatement::Tpm(honest) = &statement else {
        panic!("a TPM statement")
    };
    let b64 = base64::engine::general_purpose::STANDARD;

    // The certified Name covers the authPolicy: rewriting the published
    // policy digest is refused.
    let mut public = b64.decode(&honest.public).unwrap();
    public[12] ^= 0x01;
    let mut tampered = honest.clone();
    tampered.public = b64.encode(&public);
    assert!(matches!(
        stranger.check(&jwks, &doc(CustodyStatement::Tpm(tampered))),
        Err(KeyRefusal::NameMismatch { .. })
    ));

    // Another TPM key's public area under this key's certification: refused.
    let mut swapped = honest.clone();
    swapped.public = b64.encode(other.public());
    assert!(matches!(
        stranger.check(&jwks_for(&other), &doc(CustodyStatement::Tpm(swapped))),
        Err(KeyRefusal::NameMismatch { .. })
    ));

    // A certified name rewritten inside the signed bytes breaks the AK's
    // signature.
    let mut attest_bytes = b64.decode(&honest.certify_attest).unwrap();
    let last = attest_bytes.len() - 1;
    attest_bytes[last] ^= 0x01;
    let mut renamed = honest.clone();
    renamed.certify_attest = b64.encode(&attest_bytes);
    assert!(matches!(
        stranger.check(&jwks, &doc(CustodyStatement::Tpm(renamed))),
        Err(KeyRefusal::CertifySignature { .. })
    ));

    // The boot state moves (PCR 8): the key stops signing, and a fresh quote
    // shows its policy is not over the quoted values.
    attester.tpm().pcr_extend(8, &[0x08; 32]).unwrap();
    let d = digest(b"header.payload");
    assert!(
        sign_with_federation_key(attester.tpm(), &key, &d)
            .unwrap_err()
            .is_policy_failure()
    );
    let moved = attest(&mut attester, 0x78);
    assert!(matches!(
        moved.check(&jwks, &doc(statement.clone())),
        Err(KeyRefusal::PolicyMismatch { .. })
    ));

    // A file key is said to be one, and is never a pass.
    let (_, verdicts) = stranger
        .check(
            &jwks,
            &doc(CustodyStatement::File {
                reason: "waived".into(),
            }),
        )
        .unwrap();
    assert!(!verdicts[0].is_tpm_bound());
}
