//! Appraisal against a software TPM: every refusal and every non-affirming
//! tier is driven from an honest baseline by one perturbation (A-19), and
//! the baseline itself is shown to be `Attested` first — a test suite whose
//! honest case does not affirm proves nothing about its perturbations.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use p256::ecdsa::SigningKey;

use crate::anchor::{AkAnchor, AkAnchorClaim, AnchorPolicy, OperatorPin, UnanchoredReason};
use crate::appraise::{
    AppraisalPolicy, Divergence, FreshnessExpectation, Refusal, StaleReason, Tier,
    UnattestedReason, appraise,
};
use crate::binding::{ExecutorKey, Federation, Freshness, KeyBinding, Nonce, qualifying_data};
use crate::crypto::sha256;
use crate::eventlog::build::LogBuilder;
use crate::evidence::{BootLog, EVIDENCE_PROFILE, ImaLog, NodeEvidence, TpmQuote};
use crate::ima::{ImaLogFormat, build as ima_build};
use crate::reference::{
    CmdlineRule, DigestSet, Expect, ImaReference, ImaScope, REFERENCE_PROFILE, ReferenceManifest,
    ReferenceValues,
};
use crate::tpm::{AkPublic, build};

const SOURCE: &str = "cloud-shielded-identity:project/zone/instance";
const NOW: i64 = 1_791_000_000;
const NODE_BIN: &str = "/opt/nucleus/bin/nucleus-node";
const CMDLINE: &str = "root=/dev/vda ro ima_policy=nucleus ima_hash=sha256";

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// What the software node boots and runs.
#[derive(Clone)]
struct Boot {
    shim: [u8; 32],
    kernel: &'static [u8],
    cmdline: &'static str,
    secure_boot: bool,
    binaries: Vec<(&'static str, [u8; 32])>,
    /// Entries measured after the quote.
    late: Vec<(&'static str, [u8; 32])>,
}

fn honest_boot() -> Boot {
    Boot {
        shim: [0x51; 32],
        kernel: b"vmlinuz contents",
        cmdline: CMDLINE,
        secure_boot: true,
        binaries: vec![(NODE_BIN, [0xAA; 32])],
        late: vec![],
    }
}

fn ak() -> SigningKey {
    SigningKey::from_slice(&[0x42; 32]).unwrap()
}

fn binding() -> KeyBinding {
    KeyBinding {
        executor_key: ExecutorKey::Ed25519([0xE0; 32]),
        federation: Federation::NotFederated,
    }
}

fn nonce(b: u8) -> Nonce {
    Nonce::new(vec![b; 32]).unwrap()
}

/// The node: boot, then quote over `freshness` with `ak`.
fn node(
    boot: &Boot,
    ak: &SigningKey,
    bind: &KeyBinding,
    freshness: Freshness,
    claim: AkAnchorClaim,
) -> NodeEvidence {
    let (log, mut pcrs) = LogBuilder::new()
        .efi_app(boot.shim)
        .secure_boot(boot.secure_boot)
        .cmdline(boot.cmdline)
        .boot_file("/vmlinuz", boot.kernel)
        .finish();
    let mut pcr10 = [0u8; 32];
    let mut ima = ima_build::entry(&mut pcr10, "boot_aggregate", [1; 32]);
    for (path, d) in &boot.binaries {
        ima.extend(ima_build::entry(&mut pcr10, path, *d));
    }
    pcrs.insert(10, pcr10);
    pcrs.insert(0, [0u8; 32]);
    for (path, d) in &boot.late {
        let mut scratch = pcr10;
        ima.extend(ima_build::entry(&mut scratch, path, *d));
        pcr10 = scratch;
    }
    let selection: BTreeSet<u8> = pcrs.keys().copied().collect();
    let concat: Vec<u8> = pcrs.values().flatten().copied().collect();
    let attest = build::quote(
        &qualifying_data(bind, &freshness),
        &selection,
        &sha256(&concat),
    );
    let signature = build::sign(ak, &attest);
    NodeEvidence {
        eat_profile: EVIDENCE_PROFILE.into(),
        binding: bind.clone(),
        freshness,
        tpm: TpmQuote {
            ak_public: b64(&build::p256_public(
                ak.verifying_key(),
                build::AK_ATTRIBUTES,
            )),
            attest: b64(&attest),
            signature: b64(&signature),
            pcrs: pcrs.iter().map(|(k, v)| (*k, hex::encode(v))).collect(),
        },
        boot_event_log: BootLog::Attached(b64(&log)),
        ima_log: ImaLog::Attached {
            format: ImaLogFormat::Sha256TemplateDigests,
            log: b64(&ima),
        },
        ak_anchor: claim,
    }
}

fn honest(freshness: Freshness) -> NodeEvidence {
    node(
        &honest_boot(),
        &ak(),
        &binding(),
        freshness,
        AkAnchorClaim::OperatorFetched {
            source: SOURCE.into(),
        },
    )
}

fn reference() -> ReferenceManifest {
    let h = honest_boot();
    let set = |d: String| DigestSet {
        allowed: [d.clone()].into_iter().collect(),
        required: [d].into_iter().collect(),
    };
    ReferenceManifest {
        profile: REFERENCE_PROFILE.into(),
        tag_id: "test-node".into(),
        reference_values: ReferenceValues {
            pcrs: BTreeMap::new(),
            secure_boot: Expect::Required(true),
            efi_applications: Expect::Required(set(hex::encode(h.shim))),
            boot_files: Expect::Required(set(hex::encode(sha256(h.kernel)))),
            kernel_cmdline: Expect::Required(CmdlineRule::Exact(CMDLINE.into())),
            ima: Expect::Required(ImaReference {
                scope: ImaScope::AllMeasured,
                allowlist: [(
                    NODE_BIN.to_string(),
                    [hex::encode([0xAAu8; 32])].into_iter().collect(),
                )]
                .into_iter()
                .collect(),
                required: [NODE_BIN.to_string()].into_iter().collect(),
            }),
        },
    }
}

fn pinned() -> AnchorPolicy {
    let ak_pub = AkPublic::from_tpm2b_public(&build::p256_public(
        ak().verifying_key(),
        build::AK_ATTRIBUTES,
    ))
    .unwrap();
    AnchorPolicy {
        trust_roots: vec![],
        operator_pins: vec![OperatorPin {
            source: SOURCE.into(),
            ak_spki_sha256: hex::encode(ak_pub.spki_sha256()),
        }],
    }
}

fn challenge(sent: u8) -> FreshnessExpectation {
    FreshnessExpectation::Challenge { sent: nonce(sent) }
}

fn epoch_at(receipt_time: i64) -> FreshnessExpectation {
    FreshnessExpectation::Epoch {
        receipt_time,
        max_age_secs: 600,
        max_future_secs: 30,
    }
}

fn run(
    e: &NodeEvidence,
    fresh: FreshnessExpectation,
    anchors: &AnchorPolicy,
) -> Result<crate::Appraisal, Refusal> {
    let r = reference();
    let b = binding();
    appraise(
        e,
        &AppraisalPolicy {
            expected_binding: &b,
            freshness: fresh,
            reference: &r,
            anchors,
            now: NOW,
        },
    )
}

fn challenged() -> NodeEvidence {
    honest(Freshness::Challenge {
        eat_nonce: nonce(1),
    })
}

// ---------------------------------------------------------------- baseline

#[test]
fn honest_challenge_evidence_is_attested_with_its_anchor_named() {
    let a = run(&challenged(), challenge(1), &pinned()).unwrap();
    assert_eq!(a.tier(), &Tier::Attested, "{:#?}", a.divergences());
    assert_eq!(
        a.anchor(),
        &AkAnchor::OperatorFetched {
            source: SOURCE.into()
        }
    );
    let boot = a.boot().unwrap();
    assert_eq!(boot.kernel_cmdlines, vec![CMDLINE]);
    assert_eq!(a.ima().unwrap().entries.len(), 2);
    assert_eq!(
        a.to_ear("test", NOW)["submods"]["node"]["ear.status"],
        "affirming"
    );
}

#[test]
fn honest_epoch_evidence_within_max_age_is_attested() {
    let e = honest(Freshness::Epoch {
        counter: 7,
        iat: NOW,
    });
    let a = run(&e, epoch_at(NOW + 599), &pinned()).unwrap();
    assert_eq!(a.tier(), &Tier::Attested);
}

#[test]
fn evidence_survives_a_json_round_trip() {
    let e = challenged();
    let s = serde_json::to_vec(&e).unwrap();
    let back: NodeEvidence = serde_json::from_slice(&s).unwrap();
    assert_eq!(back, e);
    assert_eq!(
        run(&back, challenge(1), &pinned()).unwrap().tier(),
        &Tier::Attested
    );
}

// --------------------------------------------------------------- freshness

#[test]
fn a_replayed_challenge_quote_is_expired() {
    // The node answered nonce 1; this verifier sent nonce 2.
    let a = run(&challenged(), challenge(2), &pinned()).unwrap();
    assert_eq!(
        a.tier(),
        &Tier::Expired {
            reason: StaleReason::NonceMismatch
        }
    );
    assert_eq!(
        a.to_ear("t", NOW)["submods"]["node"]["ear.status"],
        "warning"
    );
}

#[test]
fn rewriting_the_nonce_without_requoting_is_refused() {
    let mut e = challenged();
    e.freshness = Freshness::Challenge {
        eat_nonce: nonce(2),
    };
    assert_eq!(
        run(&e, challenge(2), &pinned()).unwrap_err(),
        Refusal::QualifyingData
    );
}

#[test]
fn a_replayed_epoch_quote_is_expired() {
    let e = honest(Freshness::Epoch {
        counter: 7,
        iat: NOW,
    });
    let a = run(&e, epoch_at(NOW + 3600), &pinned()).unwrap();
    assert_eq!(
        a.tier(),
        &Tier::Expired {
            reason: StaleReason::TooOld {
                age_secs: 3600,
                max_age_secs: 600
            }
        }
    );
}

#[test]
fn rewriting_the_epoch_time_without_requoting_is_refused() {
    let mut e = honest(Freshness::Epoch {
        counter: 7,
        iat: NOW,
    });
    e.freshness = Freshness::Epoch {
        counter: 7,
        iat: NOW + 3600,
    };
    assert_eq!(
        run(&e, epoch_at(NOW + 3600), &pinned()).unwrap_err(),
        Refusal::QualifyingData
    );
}

#[test]
fn epoch_evidence_from_the_future_is_expired() {
    let e = honest(Freshness::Epoch {
        counter: 7,
        iat: NOW + 120,
    });
    let a = run(&e, epoch_at(NOW), &pinned()).unwrap();
    assert!(matches!(
        a.tier(),
        Tier::Expired {
            reason: StaleReason::FromTheFuture { ahead_secs: 120 }
        }
    ));
}

#[test]
fn mode_mismatch_is_never_fresh() {
    let a = run(&challenged(), epoch_at(NOW), &pinned()).unwrap();
    assert_eq!(
        a.tier(),
        &Tier::Expired {
            reason: StaleReason::NotEpochEvidence
        }
    );
    let e = honest(Freshness::Epoch {
        counter: 1,
        iat: NOW,
    });
    let a = run(&e, challenge(1), &pinned()).unwrap();
    assert_eq!(
        a.tier(),
        &Tier::Expired {
            reason: StaleReason::NotAChallengeResponse
        }
    );
}

// ------------------------------------------------------------- key binding

#[test]
fn evidence_for_another_executor_key_is_refused() {
    let other = KeyBinding {
        executor_key: ExecutorKey::Ed25519([0xE1; 32]),
        federation: Federation::NotFederated,
    };
    let r = reference();
    let err = appraise(
        &challenged(),
        &AppraisalPolicy {
            expected_binding: &other,
            freshness: challenge(1),
            reference: &r,
            anchors: &pinned(),
            now: NOW,
        },
    )
    .unwrap_err();
    assert_eq!(err, Refusal::ExecutorKeyMismatch);
}

#[test]
fn rebinding_to_the_receipts_key_without_requoting_is_refused() {
    // Quote taken for key E1; the JSON is edited to claim E0 (the receipt's).
    let other = KeyBinding {
        executor_key: ExecutorKey::Ed25519([0xE1; 32]),
        federation: Federation::NotFederated,
    };
    let mut e = node(
        &honest_boot(),
        &ak(),
        &other,
        Freshness::Challenge {
            eat_nonce: nonce(1),
        },
        AkAnchorClaim::OperatorFetched {
            source: SOURCE.into(),
        },
    );
    e.binding = binding();
    assert_eq!(
        run(&e, challenge(1), &pinned()).unwrap_err(),
        Refusal::QualifyingData
    );
}

#[test]
fn the_federation_set_is_part_of_the_binding() {
    let mut e = challenged();
    e.binding.federation = Federation::JwksSha256([3; 32]);
    let fed = e.binding.clone();
    let r = reference();
    let err = appraise(
        &e,
        &AppraisalPolicy {
            expected_binding: &fed,
            freshness: challenge(1),
            reference: &r,
            anchors: &pinned(),
            now: NOW,
        },
    )
    .unwrap_err();
    assert_eq!(err, Refusal::QualifyingData);
}

#[test]
fn a_federation_mismatch_names_both_sets() {
    // Quoted for a federating node; the relying party expected none.
    let fed = KeyBinding {
        executor_key: binding().executor_key,
        federation: Federation::JwksSha256([3; 32]),
    };
    let e = node(
        &honest_boot(),
        &ak(),
        &fed,
        Freshness::Challenge {
            eat_nonce: nonce(1),
        },
        AkAnchorClaim::OperatorFetched {
            source: SOURCE.into(),
        },
    );
    let err = run(&e, challenge(1), &pinned()).unwrap_err();
    assert_eq!(
        err,
        Refusal::FederationMismatch {
            expected: Federation::NotFederated,
            bound: Federation::JwksSha256([3; 32]),
        }
    );
    let msg = err.to_string();
    assert!(msg.contains(&hex::encode([3u8; 32])), "{msg}");
    assert!(msg.contains("not federated"), "{msg}");
    // Expecting that set, the same evidence is appraised.
    let r = reference();
    let a = appraise(
        &e,
        &AppraisalPolicy {
            expected_binding: &fed,
            freshness: challenge(1),
            reference: &r,
            anchors: &pinned(),
            now: NOW,
        },
    )
    .unwrap();
    assert_eq!(a.tier(), &Tier::Attested);
}

// --------------------------------------------------------- quote integrity

#[test]
fn a_flipped_supplied_pcr_is_refused() {
    let mut e = challenged();
    let v = e.tpm.pcrs.get_mut(&4).unwrap();
    let mut b = hex::decode(&*v).unwrap();
    b[0] ^= 1;
    *v = hex::encode(b);
    assert_eq!(
        run(&e, challenge(1), &pinned()).unwrap_err(),
        Refusal::PcrDigest
    );
}

#[test]
fn an_omitted_pcr_is_refused() {
    let mut e = challenged();
    e.tpm.pcrs.remove(&10);
    assert!(matches!(
        run(&e, challenge(1), &pinned()).unwrap_err(),
        Refusal::PcrSelection(_)
    ));
}

#[test]
fn a_quote_signed_by_another_key_is_refused() {
    let mut e = challenged();
    let other = SigningKey::from_slice(&[0x43; 32]).unwrap();
    let attest = base64::engine::general_purpose::STANDARD
        .decode(&e.tpm.attest)
        .unwrap();
    e.tpm.signature = b64(&build::sign(&other, &attest));
    assert_eq!(
        run(&e, challenge(1), &pinned()).unwrap_err(),
        Refusal::BadSignature
    );
}

#[test]
fn a_boot_log_that_is_not_the_quoted_boot_is_refused() {
    // Log from a boot with a different kernel, quote from the honest one.
    let mut e = challenged();
    let mut other = honest_boot();
    other.kernel = b"another kernel";
    let forged = node(
        &other,
        &ak(),
        &binding(),
        e.freshness.clone(),
        e.ak_anchor.clone(),
    );
    e.boot_event_log = forged.boot_event_log;
    assert_eq!(
        run(&e, challenge(1), &pinned()).unwrap_err(),
        Refusal::EventLogDoesNotReplay { pcr: 9 }
    );
}

#[test]
fn an_ima_log_that_is_not_the_quoted_one_is_refused() {
    let mut e = challenged();
    let mut other = honest_boot();
    other.binaries = vec![(NODE_BIN, [0xBB; 32])];
    let forged = node(
        &other,
        &ak(),
        &binding(),
        e.freshness.clone(),
        e.ak_anchor.clone(),
    );
    e.ima_log = forged.ima_log;
    assert_eq!(
        run(&e, challenge(1), &pinned()).unwrap_err(),
        Refusal::ImaLogDoesNotReplay
    );
}

// --------------------------------------------------------------- reference

#[test]
fn a_different_cmdline_is_contested_and_named() {
    let mut boot = honest_boot();
    boot.cmdline = "root=/dev/vda ro init=/bin/sh";
    let e = node(
        &boot,
        &ak(),
        &binding(),
        Freshness::Challenge {
            eat_nonce: nonce(1),
        },
        AkAnchorClaim::OperatorFetched {
            source: SOURCE.into(),
        },
    );
    let a = run(&e, challenge(1), &pinned()).unwrap();
    assert_eq!(a.tier(), &Tier::Contested);
    assert_eq!(
        a.divergences(),
        &[Divergence::KernelCmdline {
            observed: vec!["root=/dev/vda ro init=/bin/sh".into()]
        }]
    );
    assert_eq!(
        a.to_ear("t", NOW)["submods"]["node"]["ear.status"],
        "contraindicated"
    );
}

#[test]
fn a_different_kernel_is_contested_and_named() {
    let mut boot = honest_boot();
    boot.kernel = b"another kernel";
    let e = node(
        &boot,
        &ak(),
        &binding(),
        Freshness::Challenge {
            eat_nonce: nonce(1),
        },
        AkAnchorClaim::OperatorFetched {
            source: SOURCE.into(),
        },
    );
    let a = run(&e, challenge(1), &pinned()).unwrap();
    assert_eq!(a.tier(), &Tier::Contested);
    let d = a.divergences();
    assert!(d.contains(&Divergence::BootFileNotAllowed {
        digest: hex::encode(sha256(b"another kernel")),
        path_label: "/vmlinuz".into()
    }));
    assert!(d.contains(&Divergence::BootFileMissing {
        digest: hex::encode(sha256(b"vmlinuz contents"))
    }));
}

#[test]
fn secure_boot_off_is_contested() {
    let mut boot = honest_boot();
    boot.secure_boot = false;
    let e = node(
        &boot,
        &ak(),
        &binding(),
        Freshness::Challenge {
            eat_nonce: nonce(1),
        },
        AkAnchorClaim::OperatorFetched {
            source: SOURCE.into(),
        },
    );
    let a = run(&e, challenge(1), &pinned()).unwrap();
    assert_eq!(
        a.divergences(),
        &[Divergence::SecureBoot { expected: true }]
    );
}

#[test]
fn an_unlisted_binary_and_a_missing_node_binary_are_contested() {
    let mut boot = honest_boot();
    boot.binaries = vec![("/tmp/implant", [0xCC; 32])];
    let e = node(
        &boot,
        &ak(),
        &binding(),
        Freshness::Challenge {
            eat_nonce: nonce(1),
        },
        AkAnchorClaim::OperatorFetched {
            source: SOURCE.into(),
        },
    );
    let a = run(&e, challenge(1), &pinned()).unwrap();
    assert_eq!(a.tier(), &Tier::Contested);
    assert_eq!(
        a.divergences(),
        &[
            Divergence::ImaFileNotAllowed {
                path: "/tmp/implant".into(),
                digest: hex::encode([0xCCu8; 32])
            },
            Divergence::ImaRequiredMissing {
                path: NODE_BIN.into()
            }
        ]
    );
}

#[test]
fn files_measured_after_the_quote_are_not_evidence() {
    let mut boot = honest_boot();
    boot.late = vec![("/tmp/after-the-quote", [0xDD; 32])];
    let e = node(
        &boot,
        &ak(),
        &binding(),
        Freshness::Challenge {
            eat_nonce: nonce(1),
        },
        AkAnchorClaim::OperatorFetched {
            source: SOURCE.into(),
        },
    );
    let a = run(&e, challenge(1), &pinned()).unwrap();
    assert_eq!(a.tier(), &Tier::Attested);
    assert_eq!(a.ima().unwrap().unquoted_tail, 1);
}

// ------------------------------------------------------------- IMA scope

const MODULE: &str = "/usr/lib/modules/7.0.0/kernel/net/bridge/bridge.ko";

fn scoped(prefixes: &[&str]) -> ReferenceManifest {
    let mut r = reference();
    let Expect::Required(ima) = &mut r.reference_values.ima else {
        unreachable!("the baseline checks IMA")
    };
    ima.scope = ImaScope::PathPrefixes(prefixes.iter().map(|p| p.to_string()).collect());
    r
}

fn appraise_against(e: &NodeEvidence, r: &ReferenceManifest) -> crate::Appraisal {
    appraise(
        e,
        &AppraisalPolicy {
            expected_binding: &binding(),
            freshness: challenge(1),
            reference: r,
            anchors: &pinned(),
            now: NOW,
        },
    )
    .unwrap()
}

fn running(binaries: Vec<(&'static str, [u8; 32])>) -> NodeEvidence {
    let mut boot = honest_boot();
    boot.binaries = binaries;
    node(
        &boot,
        &ak(),
        &binding(),
        Freshness::Challenge {
            eat_nonce: nonce(1),
        },
        AkAnchorClaim::OperatorFetched {
            source: SOURCE.into(),
        },
    )
}

#[test]
fn a_platform_module_outside_the_scope_is_listed_not_contested() {
    let e = running(vec![(MODULE, [0x11; 32]), (NODE_BIN, [0xAA; 32])]);
    // Baseline first: unscoped, the module the reference never mentions contests.
    let all = appraise_against(&e, &reference());
    assert_eq!(all.tier(), &Tier::Contested);
    assert!(all.ima_not_in_scope().is_empty());
    // Scoped to the node's install directory, it is named, not judged.
    let a = appraise_against(&e, &scoped(&["/opt/nucleus/bin"]));
    assert_eq!(a.tier(), &Tier::Attested, "{:#?}", a.divergences());
    let listed: Vec<&str> = a.ima_not_in_scope().iter().map(|e| e.path.as_str()).collect();
    assert_eq!(listed, [MODULE]);
    let ear = a.to_ear("test", NOW);
    assert_eq!(
        ear["submods"]["node"]["nucleus.appraisal"]["ima_not_in_scope"][0]["path"],
        MODULE
    );
}

#[test]
fn an_unknown_binary_inside_the_scope_is_still_contested() {
    // A-19: the scope narrows what the reference governs, never what it
    // forgives inside it.
    let e = running(vec![
        (NODE_BIN, [0xAA; 32]),
        ("/opt/nucleus/bin/implant", [0xCC; 32]),
        (MODULE, [0x11; 32]),
    ]);
    let a = appraise_against(&e, &scoped(&["/opt/nucleus/bin"]));
    assert_eq!(a.tier(), &Tier::Contested);
    assert_eq!(
        a.divergences(),
        &[Divergence::ImaFileNotAllowed {
            path: "/opt/nucleus/bin/implant".into(),
            digest: hex::encode([0xCCu8; 32]),
        }]
    );
    // A replaced node binary in scope contests too.
    let replaced = running(vec![(NODE_BIN, [0xAB; 32])]);
    let a = appraise_against(&replaced, &scoped(&["/opt/nucleus/bin"]));
    assert_eq!(a.tier(), &Tier::Contested);
}

#[test]
fn a_required_binary_measured_only_outside_the_scope_is_missing() {
    // The node binary run from another mount is not the install the
    // reference names: listed out of scope, and the requirement unmet.
    let e = running(vec![("/mnt/elsewhere/nucleus-node", [0xAA; 32])]);
    let a = appraise_against(&e, &scoped(&["/opt/nucleus/bin"]));
    assert_eq!(a.tier(), &Tier::Contested);
    assert_eq!(
        a.divergences(),
        &[Divergence::ImaRequiredMissing {
            path: NODE_BIN.into()
        }]
    );
    assert_eq!(a.ima_not_in_scope().len(), 1);
}

#[test]
fn an_incoherent_scope_is_not_evaluable_never_attested() {
    let e = running(vec![(NODE_BIN, [0xAA; 32])]);
    for r in [scoped(&["/usr/local/bin"]), scoped(&[]), scoped(&["/opt/nucleus/bin/"])] {
        let a = appraise_against(&e, &r);
        assert_eq!(a.tier(), &Tier::Contested);
        assert!(
            matches!(
                a.divergences(),
                [Divergence::NotEvaluable { check: "ima", .. }]
            ),
            "{:#?}",
            a.divergences()
        );
    }
}

#[test]
fn absent_logs_are_not_evaluable_never_attested() {
    let mut e = challenged();
    e.boot_event_log = BootLog::Absent("platform has no event log".into());
    e.ima_log = ImaLog::Absent("IMA disabled".into());
    let a = run(&e, challenge(1), &pinned()).unwrap();
    assert_eq!(a.tier(), &Tier::Contested);
    let checks: Vec<&str> = a
        .divergences()
        .iter()
        .map(|d| match d {
            Divergence::NotEvaluable { check, .. } => *check,
            other => panic!("unexpected {other:?}"),
        })
        .collect();
    assert_eq!(
        checks,
        [
            "secure_boot",
            "efi_applications",
            "boot_files",
            "kernel_cmdline",
            "ima"
        ]
    );
}

#[test]
fn not_checked_items_are_reported_beside_an_attested_verdict() {
    let mut r = reference();
    r.reference_values.efi_applications = Expect::NotChecked("shim varies by image".into());
    let b = binding();
    let a = appraise(
        &challenged(),
        &AppraisalPolicy {
            expected_binding: &b,
            freshness: challenge(1),
            reference: &r,
            anchors: &pinned(),
            now: NOW,
        },
    )
    .unwrap();
    assert_eq!(a.tier(), &Tier::Attested);
    assert_eq!(
        a.not_checked().get("efi_applications").map(String::as_str),
        Some("shim varies by image")
    );
}

#[test]
fn a_pinned_pcr_that_differs_is_contested() {
    let mut r = reference();
    r.reference_values.pcrs.insert(0, hex::encode([9u8; 32]));
    let b = binding();
    let a = appraise(
        &challenged(),
        &AppraisalPolicy {
            expected_binding: &b,
            freshness: challenge(1),
            reference: &r,
            anchors: &pinned(),
            now: NOW,
        },
    )
    .unwrap();
    assert!(matches!(
        a.divergences(),
        [Divergence::Pcr { index: 0, .. }]
    ));
}

// ------------------------------------------------------------------ anchor

#[test]
fn an_operator_claim_without_a_pin_is_unattested() {
    let none = AnchorPolicy {
        trust_roots: vec![],
        operator_pins: vec![],
    };
    let a = run(&challenged(), challenge(1), &none).unwrap();
    assert_eq!(
        a.tier(),
        &Tier::Unattested {
            reason: UnattestedReason::AkUnanchored(UnanchoredReason::NoMatchingOperatorPin)
        }
    );
    assert_eq!(a.to_ear("t", NOW)["submods"]["node"]["ear.status"], "none");
}

#[test]
fn a_pin_for_another_source_does_not_anchor() {
    let mut p = pinned();
    p.operator_pins[0].source = "another-source".into();
    let a = run(&challenged(), challenge(1), &p).unwrap();
    assert!(matches!(a.tier(), Tier::Unattested { .. }));
}

#[test]
fn a_software_key_pinned_by_mistake_is_still_not_an_attestation_key() {
    // A key without `restricted` can sign anything, including a forged
    // TPMS_ATTEST; no pin makes its quotes evidence.
    let mut e = challenged();
    e.tpm.ak_public = b64(&build::p256_public(
        ak().verifying_key(),
        build::AK_ATTRIBUTES & !(1 << 16),
    ));
    assert_eq!(
        run(&e, challenge(1), &pinned()).unwrap_err(),
        Refusal::NotAnAttestationKey(vec!["restricted"])
    );
}

#[test]
fn unclaimed_anchor_is_unattested_even_when_everything_else_matches() {
    let mut e = challenged();
    e.ak_anchor = AkAnchorClaim::None;
    let a = run(&e, challenge(1), &pinned()).unwrap();
    assert_eq!(
        a.tier(),
        &Tier::Unattested {
            reason: UnattestedReason::AkUnanchored(UnanchoredReason::NotClaimed)
        }
    );
    assert!(a.divergences().is_empty());
}

mod chains {
    use super::*;
    use p256::pkcs8::EncodePrivateKey;
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};

    struct Pki {
        root_der: Vec<u8>,
        leaf_der: Vec<u8>,
    }

    /// A root, and a leaf certifying `subject`'s public key.
    fn pki(subject: &SigningKey) -> Pki {
        let root_key = KeyPair::generate().unwrap();
        let mut root = CertificateParams::new(Vec::<String>::new()).unwrap();
        root.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root.distinguished_name
            .push(DnType::CommonName, "test AK root");
        let root_cert = root.self_signed(&root_key).unwrap();
        let issuer = Issuer::new(root, root_key);
        let der = subject.to_pkcs8_der().unwrap();
        let leaf_key = KeyPair::try_from(der.as_bytes()).unwrap();
        let mut leaf = CertificateParams::new(Vec::<String>::new()).unwrap();
        leaf.distinguished_name.push(DnType::CommonName, "test AK");
        let leaf_cert = leaf.signed_by(&leaf_key, &issuer).unwrap();
        Pki {
            root_der: root_cert.der().to_vec(),
            leaf_der: leaf_cert.der().to_vec(),
        }
    }

    fn with_chain(chain: Vec<Vec<u8>>) -> NodeEvidence {
        let mut e = challenged();
        e.ak_anchor = AkAnchorClaim::CertificateChain {
            chain: chain.iter().map(|c| b64(c)).collect(),
        };
        e
    }

    #[test]
    fn a_chain_to_a_trusted_root_is_a_certificate_anchor() {
        let p = pki(&ak());
        let policy = AnchorPolicy {
            trust_roots: vec![p.root_der.clone()],
            operator_pins: vec![],
        };
        let a = run(&with_chain(vec![p.leaf_der]), challenge(1), &policy).unwrap();
        assert_eq!(a.tier(), &Tier::Attested);
        assert!(matches!(a.anchor(), AkAnchor::CertificateChain { .. }));
    }

    #[test]
    fn a_chain_to_an_untrusted_root_is_unattested_not_refused() {
        let p = pki(&ak());
        let other = pki(&ak());
        let policy = AnchorPolicy {
            trust_roots: vec![other.root_der],
            operator_pins: vec![],
        };
        let a = run(&with_chain(vec![p.leaf_der]), challenge(1), &policy).unwrap();
        assert_eq!(
            a.tier(),
            &Tier::Unattested {
                reason: UnattestedReason::AkUnanchored(UnanchoredReason::RootNotTrusted)
            }
        );
    }

    #[test]
    fn a_certificate_for_another_key_presented_as_the_aks_anchor_is_refused() {
        // A real, validly chained certificate — for a different key.
        let p = pki(&SigningKey::from_slice(&[0x44; 32]).unwrap());
        let policy = AnchorPolicy {
            trust_roots: vec![p.root_der.clone()],
            operator_pins: vec![],
        };
        let err = run(&with_chain(vec![p.leaf_der]), challenge(1), &policy).unwrap_err();
        assert!(matches!(err, Refusal::FalseAnchor(_)), "{err:?}");
    }

    #[test]
    fn a_tampered_certificate_is_refused() {
        let p = pki(&ak());
        let mut leaf = p.leaf_der.clone();
        // Flip a byte in the signature (the tail of the DER).
        let n = leaf.len();
        leaf[n - 3] ^= 1;
        let mid = pki(&ak());
        let policy = AnchorPolicy {
            trust_roots: vec![mid.root_der.clone(), p.root_der.clone()],
            operator_pins: vec![],
        };
        // Present leaf + its root so the link signature is checked in-chain.
        let err = run(
            &with_chain(vec![leaf, p.root_der.clone()]),
            challenge(1),
            &policy,
        )
        .unwrap_err();
        assert!(matches!(err, Refusal::FalseAnchor(_)), "{err:?}");
    }
}

mod fuzz {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// No single-byte change to the signed structure or its signature
        /// leaves an `Attested` result.
        #[test]
        fn no_single_byte_flip_is_attested(which in 0usize..2, pos in any::<prop::sample::Index>(), bit in 0u8..8) {
            let mut e = challenged();
            let field = if which == 0 { &mut e.tpm.attest } else { &mut e.tpm.signature };
            let mut bytes = base64::engine::general_purpose::STANDARD.decode(&*field).unwrap();
            let i = pos.index(bytes.len());
            bytes[i] ^= 1 << bit;
            *field = b64(&bytes);
            let attested = run(&e, challenge(1), &pinned())
                .is_ok_and(|a| a.tier() == &Tier::Attested);
            prop_assert!(!attested);
        }
    }
}
