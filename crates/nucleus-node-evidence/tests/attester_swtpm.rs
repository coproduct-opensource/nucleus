//! The attester against a software TPM, checked by the verifier.
//!
//! Needs a running swtpm (`swtpm socket --tpm2 --server type=tcp,port=P
//! --ctrl type=tcp,port=P+1 --flags not-need-init,startup-clear`) at
//! `NUCLEUS_SWTPM_ADDR`, with the default ECC AK template written to NV index
//! `0x01c10003` for the NV-template test. Ignored by default; an ignored test
//! is reported as ignored, never as a pass.
#![cfg(feature = "attester")]

use std::collections::BTreeSet;

use nucleus_node_evidence::attester::{
    AkTemplate, Attester, LogSources, SocketTransport, Tpm, default_pcrs,
};
use nucleus_node_evidence::tpm::AkPublic;
use nucleus_node_evidence::{
    AkAnchor, AkAnchorClaim, AnchorPolicy, AppraisalPolicy, BootLog, ExecutorKey, Expect,
    Federation, Freshness, FreshnessExpectation, ImaLog, KeyBinding, Nonce, OperatorPin,
    REFERENCE_PROFILE, ReferenceManifest, ReferenceValues, StaleReason, Tier, appraise,
};

const SOURCE: &str = "swtpm-operator";

fn tpm() -> Tpm<SocketTransport> {
    let addr = std::env::var("NUCLEUS_SWTPM_ADDR").expect("NUCLEUS_SWTPM_ADDR");
    Tpm::new(SocketTransport::connect(&addr).unwrap())
}

fn no_logs() -> LogSources {
    LogSources {
        boot_event_log: "/nonexistent/boot".into(),
        ima_sha256: "/nonexistent/ima256".into(),
        ima_sha1: "/nonexistent/ima1".into(),
    }
}

fn attester(template: AkTemplate) -> Attester<SocketTransport> {
    Attester::new(
        tpm(),
        template,
        [0u8, 16].into_iter().collect::<BTreeSet<_>>(),
        no_logs(),
        AkAnchorClaim::OperatorFetched {
            source: SOURCE.into(),
        },
    )
}

fn binding() -> KeyBinding {
    KeyBinding {
        executor_key: ExecutorKey::Ed25519([0x5e; 32]),
        federation: Federation::JwksSha256([0x1f; 32]),
    }
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

fn pin_for(ak_public: &[u8]) -> AnchorPolicy {
    let ak = AkPublic::from_tpm2b_public(ak_public).unwrap();
    AnchorPolicy {
        trust_roots: vec![],
        operator_pins: vec![OperatorPin {
            source: SOURCE.into(),
            ak_spki_sha256: hex::encode(ak.spki_sha256()),
        }],
    }
}

#[test]
#[ignore = "needs a running swtpm at NUCLEUS_SWTPM_ADDR"]
fn the_attesters_challenge_evidence_is_attested_by_the_verifier() {
    let mut a = attester(AkTemplate::DefaultEccP256);
    let ak_public = a.ak_public().unwrap();
    let nonce = Nonce::new(vec![0x77; 32]).unwrap();
    let e = a
        .attest(
            &binding(),
            Freshness::Challenge {
                eat_nonce: nonce.clone(),
            },
        )
        .unwrap();
    assert!(matches!(e.boot_event_log, BootLog::Absent(_)));
    assert!(matches!(e.ima_log, ImaLog::Absent(_)));
    let b = binding();
    let r = reference();
    let anchors = pin_for(&ak_public);
    let appraised = appraise(
        &e,
        &AppraisalPolicy {
            expected_binding: &b,
            freshness: FreshnessExpectation::Challenge { sent: nonce },
            reference: &r,
            anchors: &anchors,
            now: 1_791_000_000,
        },
    )
    .unwrap();
    assert_eq!(appraised.tier(), &Tier::Attested);
    assert_eq!(
        appraised.anchor(),
        &AkAnchor::OperatorFetched {
            source: SOURCE.into()
        }
    );
    // The same evidence answering someone else's challenge is a replay.
    let other = Nonce::new(vec![0x78; 32]).unwrap();
    let replay = appraise(
        &e,
        &AppraisalPolicy {
            expected_binding: &b,
            freshness: FreshnessExpectation::Challenge { sent: other },
            reference: &r,
            anchors: &anchors,
            now: 1_791_000_000,
        },
    )
    .unwrap();
    assert_eq!(
        replay.tier(),
        &Tier::Expired {
            reason: StaleReason::NonceMismatch
        }
    );
}

#[test]
#[ignore = "needs a running swtpm at NUCLEUS_SWTPM_ADDR"]
fn epoch_evidence_round_trips_and_ages_out() {
    let mut a = attester(AkTemplate::DefaultEccP256);
    let ak_public = a.ak_public().unwrap();
    let e = a
        .attest(
            &binding(),
            Freshness::Epoch {
                counter: 9,
                iat: 1_791_000_000,
            },
        )
        .unwrap();
    let doc = serde_json::to_vec(&e).unwrap();
    let back: nucleus_node_evidence::NodeEvidence = serde_json::from_slice(&doc).unwrap();
    let b = binding();
    let r = reference();
    let anchors = pin_for(&ak_public);
    let at = |t| FreshnessExpectation::Epoch {
        receipt_time: t,
        max_age_secs: 600,
        max_future_secs: 30,
    };
    let fresh = appraise(
        &back,
        &AppraisalPolicy {
            expected_binding: &b,
            freshness: at(1_791_000_100),
            reference: &r,
            anchors: &anchors,
            now: 1_791_000_100,
        },
    )
    .unwrap();
    assert_eq!(fresh.tier(), &Tier::Attested);
    let stale = appraise(
        &back,
        &AppraisalPolicy {
            expected_binding: &b,
            freshness: at(1_791_009_000),
            reference: &r,
            anchors: &anchors,
            now: 1_791_009_000,
        },
    )
    .unwrap();
    assert!(matches!(stale.tier(), Tier::Expired { .. }));
}

#[test]
#[ignore = "needs a running swtpm at NUCLEUS_SWTPM_ADDR with the AK template in NV 0x01c10003"]
fn an_nv_template_yields_the_same_ak_as_the_template_itself() {
    let from_nv = attester(AkTemplate::NvIndex(0x01c1_0003))
        .ak_public()
        .unwrap();
    let direct = attester(AkTemplate::DefaultEccP256).ak_public().unwrap();
    assert_eq!(from_nv, direct);
    // And every PCR the default selection names is readable.
    let pcrs = tpm().pcr_read(&default_pcrs()).unwrap();
    assert_eq!(
        pcrs.keys().copied().collect::<BTreeSet<_>>(),
        default_pcrs()
    );
}
