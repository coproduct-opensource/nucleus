//! Appraisal of evidence produced by real TPMs and an independent TPM stack.
//!
//! The software-TPM tests inside the crate prove the logic; these prove the
//! parsers agree with TPMs this crate did not write. Each fixture's quote,
//! signature and AK came from `tpm2-tools` 5.6 talking to a TPM; only the JSON
//! framing is this crate's (`examples/assemble_evidence.rs`). Each reference
//! value below was computed from files on the measured machine (`sha256sum`)
//! or from the TPM directly (`tpm2_pcrread`), never copied out of the log it
//! is compared with.
//!
//! # `vtpm-*` — a cloud Shielded VM's vTPM (2026-10-05)
//!
//! x86 n2-standard-2, Ubuntu 24.04, kernel 7.0.0-1011, Secure Boot on. The AK
//! is the provider's ECC AK, re-created from its NV template (`0x01c10003`)
//! under the endorsement hierarchy:
//!
//! ```text
//! tpm2_nvread 0x1c10003 -C o -o tmpl.bin
//! tpm2_createprimary -C e -g sha256 -G ecc256:ecdsa-sha256:null \
//!   -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign" \
//!   -u unique.bin -c ak.ctx --template-data used.bin   # cmp used.bin tmpl.bin: equal
//! tpm2_readpublic -c ak.ctx -o ak.pub
//! ```
//!
//! [`VTPM_AK_PIN`] is SHA-256 of the SubjectPublicKeyInfo of the
//! `eccP256SigningKey` the provider's API returned for that instance
//! (`gcloud compute instances get-shielded-identity`, through `openssl pkey
//! -pubin -outform DER | sha256sum`) — the operator-fetched anchor. It equals
//! the AK above, which is what makes that anchor mean anything.
//!
//! A narrow IMA policy measured only executables on the node's install
//! filesystem, plus the kernel modules the platform's own Secure Boot policy
//! measures:
//!
//! ```text
//! mkfs.ext4 -U 6e75636c-6575-4d00-8000-000000000001 ...; mount ... /opt/nucleus
//! echo "measure func=BPRM_CHECK fsuuid=6e75636c-..." > /sys/kernel/security/ima/policy
//! ```
//!
//! Then two quotes over SHA-256 PCRs 0-10 and 14, one over a challenge nonce,
//! one over an epoch (`counter 1, iat 1791244156`), with qualifying data from
//! `assemble_evidence qualifying-data`:
//!
//! ```text
//! tpm2_quote -c ak.ctx -l sha256:0,1,2,3,4,5,6,7,8,9,10,14 -q $QD \
//!   -m quote.msg -s quote.sig -o pcrs.bin -F values -g sha256
//! ```
//!
//! `vtpm-reference.json` was written by `cargo xtask node-reference-manifest`
//! from `vtpm-bootfiles.sha256` and `vtpm-ima-files.sha256`, both `sha256sum`
//! over the files on that VM. The VM was deleted after capture.
//!
//! # `swtpm-*` — libtpms through swtpm 0.7.3
//!
//! An RSA-2048 RSASSA AK under an RSA EK (`tpm2_createek`, `tpm2_createak -G
//! rsa -s rsassa`), PCR 16 extended once, quoted over PCRs 0 and 16. No event
//! log or IMA: a software TPM has no firmware. This is the RSA path.

use nucleus_node_evidence::{
    AkAnchor, AnchorPolicy, Appraisal, AppraisalPolicy, CmdlineRule, Divergence, Expect, Freshness,
    FreshnessExpectation, NodeEvidence, OperatorPin, REFERENCE_PROFILE, ReferenceManifest,
    ReferenceValues, Refusal, StaleReason, Tier, UnanchoredReason, UnattestedReason, appraise,
};

const VTPM_AK_PIN: &str = "099de433a6d31eb05252dc44fc02f74d4366c01b5cad7dcb80afe2f341bd5bc3";
const VTPM_SOURCE: &str = "gcp-shielded-vm-identity:fixture-vm";
const VTPM_EPOCH_IAT: i64 = 1_791_244_156;
const VTPM_KERNEL: &str = "d99d5fe55b545db18594e22b72f9c1430ef61af0bd3ff479830b489107678b09";

const SWTPM_AK_PIN: &str = "5347b8bd780ebbb145cdc4a3eb16c1fb4502ea80188f34cfaa9fb69ddc69f0fc";
/// `tpm2_pcrread sha256:16` after the extend.
const SWTPM_PCR16: &str = "80b505e18adda4119ca6a9abf09405eca9bc1bc8fc7a84ffccb55a6a8f8ab301";

fn evidence(name: &str) -> NodeEvidence {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap()
}

fn vtpm_reference() -> ReferenceManifest {
    let path = format!(
        "{}/tests/fixtures/vtpm-reference.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap()
}

fn pins(source: &str, pin: &str) -> AnchorPolicy {
    AnchorPolicy {
        trust_roots: vec![],
        operator_pins: vec![OperatorPin {
            source: source.into(),
            ak_spki_sha256: pin.into(),
        }],
    }
}

fn challenge_of(e: &NodeEvidence) -> FreshnessExpectation {
    match &e.freshness {
        Freshness::Challenge { eat_nonce } => FreshnessExpectation::Challenge {
            sent: eat_nonce.clone(),
        },
        Freshness::Epoch { .. } => panic!("not a challenge fixture"),
    }
}

fn appraise_with(
    e: &NodeEvidence,
    reference: &ReferenceManifest,
    anchors: &AnchorPolicy,
    freshness: FreshnessExpectation,
) -> Result<Appraisal, Refusal> {
    let binding = e.binding.clone();
    appraise(
        e,
        &AppraisalPolicy {
            expected_binding: &binding,
            freshness,
            reference,
            anchors,
            now: VTPM_EPOCH_IAT,
        },
    )
}

fn vtpm_challenge() -> (NodeEvidence, Result<Appraisal, Refusal>) {
    let e = evidence("vtpm-challenge-evidence.json");
    let r = appraise_with(
        &e,
        &vtpm_reference(),
        &pins(VTPM_SOURCE, VTPM_AK_PIN),
        challenge_of(&e),
    );
    (e, r)
}

#[test]
fn a_cloud_vtpm_quote_is_attested_under_the_operator_fetched_anchor() {
    let (_, a) = vtpm_challenge();
    let a = a.unwrap();
    assert_eq!(a.tier(), &Tier::Attested, "{:#?}", a.divergences());
    assert_eq!(
        a.anchor(),
        &AkAnchor::OperatorFetched {
            source: VTPM_SOURCE.into()
        }
    );
    assert_eq!(a.quote().ak_spki_sha256, VTPM_AK_PIN);
    assert_eq!(a.quote().ak_family, "ecdsa-p256");
    let boot = a.boot().unwrap();
    assert_eq!(
        boot.verified_pcrs,
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 14].into_iter().collect()
    );
    assert!(!boot.efi_applications.is_empty(), "shim/GRUB/kernel loads");
    assert!(boot.boot_files.iter().any(|f| f.sha256 == VTPM_KERNEL));
    assert_eq!(boot.kernel_cmdlines.len(), 1);
    let ima = a.ima().unwrap();
    assert_eq!(ima.entries.first().unwrap().path, "boot_aggregate");
    assert!(
        ima.entries
            .iter()
            .any(|e| e.path == "/opt/nucleus/bin/nucleus-node")
    );
    // The reference left exactly one item unchecked, and says so.
    assert_eq!(
        a.not_checked().keys().copied().collect::<Vec<_>>(),
        ["efi_applications"]
    );
}

#[test]
fn a_replayed_cloud_vtpm_quote_is_expired() {
    let e = evidence("vtpm-challenge-evidence.json");
    let other = FreshnessExpectation::Challenge {
        sent: nucleus_node_evidence::Nonce::new(vec![0x11; 32]).unwrap(),
    };
    let a = appraise_with(
        &e,
        &vtpm_reference(),
        &pins(VTPM_SOURCE, VTPM_AK_PIN),
        other,
    )
    .unwrap();
    assert_eq!(
        a.tier(),
        &Tier::Expired {
            reason: StaleReason::NonceMismatch
        }
    );
}

#[test]
fn cloud_vtpm_epoch_evidence_is_attested_within_age_and_expired_beyond() {
    let e = evidence("vtpm-epoch-evidence.json");
    let at = |receipt_time| FreshnessExpectation::Epoch {
        receipt_time,
        max_age_secs: 900,
        max_future_secs: 30,
    };
    let anchors = pins(VTPM_SOURCE, VTPM_AK_PIN);
    let a = appraise_with(&e, &vtpm_reference(), &anchors, at(VTPM_EPOCH_IAT + 300)).unwrap();
    assert_eq!(a.tier(), &Tier::Attested, "{:#?}", a.divergences());
    let stale = appraise_with(&e, &vtpm_reference(), &anchors, at(VTPM_EPOCH_IAT + 7200)).unwrap();
    assert_eq!(
        stale.tier(),
        &Tier::Expired {
            reason: StaleReason::TooOld {
                age_secs: 7200,
                max_age_secs: 900
            }
        }
    );
}

#[test]
fn the_same_quote_against_a_verity_cmdline_reference_is_contested() {
    let e = evidence("vtpm-challenge-evidence.json");
    let mut r = vtpm_reference();
    r.reference_values.kernel_cmdline = Expect::Required(CmdlineRule::RequiredParams(
        ["roothash=00ff".to_string()].into_iter().collect(),
    ));
    let a = appraise_with(&e, &r, &pins(VTPM_SOURCE, VTPM_AK_PIN), challenge_of(&e)).unwrap();
    assert_eq!(a.tier(), &Tier::Contested);
    assert!(matches!(
        a.divergences(),
        [Divergence::KernelCmdline { .. }]
    ));
}

#[test]
fn the_same_quote_against_another_kernel_is_contested() {
    let e = evidence("vtpm-challenge-evidence.json");
    let mut r = vtpm_reference();
    let Expect::Required(set) = &mut r.reference_values.boot_files else {
        panic!("boot files are required in the fixture reference")
    };
    set.allowed.remove(VTPM_KERNEL);
    set.required = ["00".repeat(32)].into_iter().collect();
    let a = appraise_with(&e, &r, &pins(VTPM_SOURCE, VTPM_AK_PIN), challenge_of(&e)).unwrap();
    assert_eq!(a.tier(), &Tier::Contested);
    let d = a.divergences();
    assert!(d.iter().any(|x| matches!(
        x,
        Divergence::BootFileNotAllowed { digest, .. } if digest == VTPM_KERNEL
    )));
    assert!(
        d.iter()
            .any(|x| matches!(x, Divergence::BootFileMissing { .. }))
    );
}

#[test]
fn an_unlisted_executable_is_contested() {
    let e = evidence("vtpm-challenge-evidence.json");
    let mut r = vtpm_reference();
    let Expect::Required(ima) = &mut r.reference_values.ima else {
        panic!("ima is required in the fixture reference")
    };
    ima.allowlist.remove("/opt/nucleus/bin/firecracker");
    ima.required.remove("/opt/nucleus/bin/firecracker");
    let a = appraise_with(&e, &r, &pins(VTPM_SOURCE, VTPM_AK_PIN), challenge_of(&e)).unwrap();
    assert!(matches!(
        a.divergences(),
        [Divergence::ImaFileNotAllowed { path, .. }] if path == "/opt/nucleus/bin/firecracker"
    ));
}

#[test]
fn without_the_operators_pin_the_cloud_vtpm_is_unattested() {
    let e = evidence("vtpm-challenge-evidence.json");
    let none = AnchorPolicy {
        trust_roots: vec![],
        operator_pins: vec![],
    };
    let a = appraise_with(&e, &vtpm_reference(), &none, challenge_of(&e)).unwrap();
    assert_eq!(
        a.tier(),
        &Tier::Unattested {
            reason: UnattestedReason::AkUnanchored(UnanchoredReason::NoMatchingOperatorPin)
        }
    );
    // A pin for another key under the same source does not anchor either.
    let wrong = pins(VTPM_SOURCE, SWTPM_AK_PIN);
    let a = appraise_with(&e, &vtpm_reference(), &wrong, challenge_of(&e)).unwrap();
    assert!(matches!(a.tier(), Tier::Unattested { .. }));
}

#[test]
fn the_cloud_vtpm_quote_for_another_executor_key_is_refused() {
    let e = evidence("vtpm-challenge-evidence.json");
    let mut other = e.binding.clone();
    other.executor_key = nucleus_node_evidence::ExecutorKey::Ed25519([0xE1; 32]);
    let r = vtpm_reference();
    let anchors = pins(VTPM_SOURCE, VTPM_AK_PIN);
    let err = appraise(
        &e,
        &AppraisalPolicy {
            expected_binding: &other,
            freshness: challenge_of(&e),
            reference: &r,
            anchors: &anchors,
            now: VTPM_EPOCH_IAT,
        },
    )
    .unwrap_err();
    assert_eq!(err, Refusal::BindingMismatch);
}

#[test]
fn a_flipped_pcr_in_the_cloud_vtpm_evidence_is_refused() {
    let mut e = evidence("vtpm-challenge-evidence.json");
    let v = e.tpm.pcrs.get_mut(&7).unwrap();
    let mut b = hex::decode(&*v).unwrap();
    b[31] ^= 0x80;
    *v = hex::encode(b);
    let err = appraise_with(
        &e,
        &vtpm_reference(),
        &pins(VTPM_SOURCE, VTPM_AK_PIN),
        challenge_of(&e),
    )
    .unwrap_err();
    assert_eq!(err, Refusal::PcrDigest);
}

#[test]
fn a_rewritten_boot_log_digest_is_refused() {
    use base64::Engine as _;
    let mut e = evidence("vtpm-challenge-evidence.json");
    let nucleus_node_evidence::BootLog::Attached(b) = &e.boot_event_log else {
        panic!("the fixture attaches its log")
    };
    let mut log = base64::engine::general_purpose::STANDARD.decode(b).unwrap();
    // Swap the kernel's measured digest for zeros: the description is
    // untouched, but PCR 9 no longer replays.
    let kernel = hex::decode(VTPM_KERNEL).unwrap();
    let at = log
        .windows(32)
        .position(|w| w == kernel.as_slice())
        .expect("the kernel digest is in the log");
    log[at..at + 32].fill(0);
    e.boot_event_log = nucleus_node_evidence::BootLog::attach(&log);
    let err = appraise_with(
        &e,
        &vtpm_reference(),
        &pins(VTPM_SOURCE, VTPM_AK_PIN),
        challenge_of(&e),
    )
    .unwrap_err();
    assert_eq!(err, Refusal::EventLogDoesNotReplay { pcr: 9 });
}

fn swtpm_reference(pcr16: &str) -> ReferenceManifest {
    fn none<T>() -> Expect<T> {
        Expect::NotChecked("a software TPM has no firmware event log".into())
    }
    ReferenceManifest {
        profile: REFERENCE_PROFILE.into(),
        tag_id: "fixture-swtpm".into(),
        reference_values: ReferenceValues {
            pcrs: [(16, pcr16.to_string())].into_iter().collect(),
            secure_boot: none(),
            efi_applications: none(),
            boot_files: none(),
            kernel_cmdline: none(),
            ima: Expect::NotChecked("IMA is not running against a software TPM".into()),
        },
    }
}

#[test]
fn an_rsa_quote_from_a_software_tpm_is_attested_against_a_pinned_pcr() {
    let e = evidence("swtpm-rsa-evidence.json");
    let a = appraise_with(
        &e,
        &swtpm_reference(SWTPM_PCR16),
        &pins("swtpm-fixture", SWTPM_AK_PIN),
        challenge_of(&e),
    )
    .unwrap();
    assert_eq!(a.tier(), &Tier::Attested, "{:#?}", a.divergences());
    assert_eq!(a.quote().ak_family, "rsa");
    assert!(a.boot().is_none() && a.ima().is_none());
    assert_eq!(a.not_checked().len(), 5);
}

#[test]
fn the_software_tpm_quote_against_another_pcr_value_is_contested() {
    let e = evidence("swtpm-rsa-evidence.json");
    let a = appraise_with(
        &e,
        &swtpm_reference(&"00".repeat(32)),
        &pins("swtpm-fixture", SWTPM_AK_PIN),
        challenge_of(&e),
    )
    .unwrap();
    assert!(matches!(
        a.divergences(),
        [Divergence::Pcr { index: 16, .. }]
    ));
}

#[test]
fn a_tampered_rsa_signature_is_refused() {
    use base64::Engine as _;
    let mut e = evidence("swtpm-rsa-evidence.json");
    let mut sig = base64::engine::general_purpose::STANDARD
        .decode(&e.tpm.signature)
        .unwrap();
    let n = sig.len();
    sig[n - 1] ^= 1;
    e.tpm.signature = base64::engine::general_purpose::STANDARD.encode(sig);
    let err = appraise_with(
        &e,
        &swtpm_reference(SWTPM_PCR16),
        &pins("swtpm-fixture", SWTPM_AK_PIN),
        challenge_of(&e),
    )
    .unwrap_err();
    assert_eq!(err, Refusal::BadSignature);
}
