//! Evidence the node's own attester produced on a real cloud vTPM, during the
//! live run recorded in `docs/findings/attested-node-live-run.md` (#2706 PR-3).
//!
//! * `live-node-epoch4-evidence.json` is the epoch document a Firecracker
//!   pod's signed execution receipt named (`evidence_sha256 d0689ce4…`,
//!   epoch 4); this file's SHA-256 is that digest.
//! * `live-node-perturbed-challenge-evidence.json` is a challenge quote from
//!   the same VM after it was rebooted with `nucleus.perturbed=1` appended to
//!   the kernel command line (and `update-grub` therefore rewrote grub.cfg).
//!
//! The AK pin is SHA-256 of the SubjectPublicKeyInfo the cloud provider's API
//! returned for that VM (`get-shielded-identity`, `eccP256SigningKey`), so
//! these tests exercise the `OperatorFetched` anchor with a real pin. The
//! reference values come from `sha256sum` on the VM's `/boot` files
//! (`live-node-bootfiles.sha256`); IMA is checked in the findings run against
//! the full module set, which is too large to commit.

use std::collections::BTreeSet;

use nucleus_node_evidence::{
    AkAnchor, AnchorPolicy, AppraisalPolicy, CmdlineRule, DigestSet, Divergence, Expect,
    FreshnessExpectation, NodeEvidence, Nonce, OperatorPin, REFERENCE_PROFILE, ReferenceManifest,
    ReferenceValues, Tier, appraise, evidence_digest,
};

const PIN: &str = "beced81752041938278acd53c5df51df98652f58bb76bdf722e8965d25bd2366";
const SOURCE: &str = "gcp-shielded-vm-identity:attest-live-x86";
const RECEIPT_DIGEST: &str = "d0689ce45219cf0e9e7827e0988c00a0a8545df93f773339734d92f44837bcab";
const EPOCH4_IAT: i64 = 1_791_247_232;
const PERTURBED_NONCE: &str = "763aaf0c5d38195380cd11f0266436c2d78307da527bf47c9d32bd6cebb07c3d";
const KERNEL: &str = "/boot/vmlinuz-7.0.0-1011-gcp";
const HONEST_WORDS: [&str; 5] = [
    "/vmlinuz-7.0.0-1011-gcp",
    "root=PARTUUID=25738ee1-aeb2-42e1-895b-9a587dbb9157",
    "ro",
    "console=ttyS0,115200",
    "panic=-1",
];

fn bytes(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn evidence(name: &str) -> NodeEvidence {
    serde_json::from_slice(&bytes(name)).unwrap()
}

fn reference(cmdline: CmdlineRule) -> ReferenceManifest {
    let listing = String::from_utf8(bytes("live-node-bootfiles.sha256")).unwrap();
    let mut boot = DigestSet {
        allowed: BTreeSet::new(),
        required: BTreeSet::new(),
    };
    for line in listing.lines() {
        let (digest, path) = line.split_once("  ").unwrap();
        boot.allowed.insert(digest.to_string());
        if path == KERNEL {
            boot.required.insert(digest.to_string());
        }
    }
    ReferenceManifest {
        profile: REFERENCE_PROFILE.into(),
        tag_id: "live-run".into(),
        reference_values: ReferenceValues {
            pcrs: Default::default(),
            secure_boot: Expect::Required(true),
            efi_applications: Expect::NotChecked("Authenticode digests not generated".into()),
            boot_files: Expect::Required(boot),
            kernel_cmdline: Expect::Required(cmdline),
            ima: Expect::NotChecked("checked in the live run against the full module set".into()),
        },
    }
}

fn exact() -> CmdlineRule {
    CmdlineRule::ExactParams(HONEST_WORDS.iter().map(|s| s.to_string()).collect())
}

fn pinned() -> AnchorPolicy {
    AnchorPolicy {
        trust_roots: vec![],
        operator_pins: vec![OperatorPin {
            source: SOURCE.into(),
            ak_spki_sha256: PIN.into(),
        }],
    }
}

fn run(
    e: &NodeEvidence,
    r: &ReferenceManifest,
    f: FreshnessExpectation,
) -> nucleus_node_evidence::Appraisal {
    let b = e.binding.clone();
    appraise(
        e,
        &AppraisalPolicy {
            expected_binding: &b,
            freshness: f,
            reference: r,
            anchors: &pinned(),
            now: EPOCH4_IAT,
        },
    )
    .unwrap()
}

fn at(receipt_time: i64) -> FreshnessExpectation {
    FreshnessExpectation::Epoch {
        receipt_time,
        max_age_secs: 900,
        max_future_secs: 60,
    }
}

fn perturbed_nonce() -> FreshnessExpectation {
    FreshnessExpectation::Challenge {
        sent: Nonce::new(hex::decode(PERTURBED_NONCE).unwrap()).unwrap(),
    }
}

#[test]
fn the_fixture_is_the_document_the_receipt_named() {
    assert_eq!(
        hex::encode(evidence_digest(&bytes("live-node-epoch4-evidence.json"))),
        RECEIPT_DIGEST
    );
}

#[test]
fn the_attesters_epoch_evidence_from_a_cloud_vtpm_is_attested() {
    let a = run(
        &evidence("live-node-epoch4-evidence.json"),
        &reference(exact()),
        at(EPOCH4_IAT + 30),
    );
    assert_eq!(a.tier(), &Tier::Attested, "{:#?}", a.divergences());
    assert_eq!(
        a.anchor(),
        &AkAnchor::OperatorFetched {
            source: SOURCE.into()
        }
    );
    assert_eq!(a.quote().ak_spki_sha256, PIN);
    let ima = a.ima().unwrap();
    for bin in ["nucleus-node", "firecracker", "jailer"] {
        assert!(
            ima.entries
                .iter()
                .any(|e| e.path == format!("/opt/nucleus/bin/{bin}")),
            "{bin} was measured"
        );
    }
}

#[test]
fn the_same_epoch_an_hour_later_is_expired() {
    let a = run(
        &evidence("live-node-epoch4-evidence.json"),
        &reference(exact()),
        at(EPOCH4_IAT + 3600),
    );
    assert!(matches!(a.tier(), Tier::Expired { .. }));
}

#[test]
fn a_reboot_with_an_added_parameter_is_contested_and_both_changes_are_named() {
    let a = run(
        &evidence("live-node-perturbed-challenge-evidence.json"),
        &reference(exact()),
        perturbed_nonce(),
    );
    assert_eq!(a.tier(), &Tier::Contested);
    let d = a.divergences();
    assert!(d.iter().any(|x| matches!(
        x,
        Divergence::KernelCmdline { observed } if observed[0].contains("nucleus.perturbed=1")
    )));
    assert!(d.iter().any(|x| matches!(
        x,
        Divergence::BootFileNotAllowed { path_label, .. } if path_label.ends_with("grub/grub.cfg")
    )));
}

#[test]
fn required_params_alone_misses_an_added_parameter() {
    // The live finding that motivated ExactParams: under RequiredParams the
    // command line raises nothing; only the rewritten grub.cfg is caught.
    let a = run(
        &evidence("live-node-perturbed-challenge-evidence.json"),
        &reference(CmdlineRule::RequiredParams(
            HONEST_WORDS[1..].iter().map(|s| s.to_string()).collect(),
        )),
        perturbed_nonce(),
    );
    assert!(
        !a.divergences()
            .iter()
            .any(|x| matches!(x, Divergence::KernelCmdline { .. }))
    );
    assert!(matches!(
        a.divergences(),
        [Divergence::BootFileNotAllowed { .. }]
    ));
}
