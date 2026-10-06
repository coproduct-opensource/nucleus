//! Evidence from the attested journey re-run (2026-10-06, release v2.5.0, an
//! x86 Shielded VM with Secure Boot), appraised against that release's own
//! reference manifest (#3276, #3277).
//!
//! * `attested-journey-epoch8-evidence.json` is the epoch-8 document the run's
//!   signed execution receipt named: its SHA-256 is that receipt's
//!   `node_platform.evidence.evidence_sha256`.
//! * `release-2.5.0-x86_64.node-reference.json` is the manifest the v2.5.0
//!   release published and Sigstore-signed, byte for byte. It predates IMA
//!   scopes, so it governs every measured file.
//!
//! The node keeps its three binaries on a dedicated read-only filesystem
//! mounted at `/usr/local/bin`, and its IMA policy measures that filesystem by
//! `fsuuid`. The platform's Secure Boot policy additionally measures every
//! kernel module it loads: 64 of them in this log. The release vouches for
//! none of those, so against the published manifest the evidence is
//! `Contested`; against the same manifest scoped to the install directory — what
//! `cargo xtask release-reference-manifest emit` now writes — it is `Attested`
//! with the 64 modules listed as not in scope.

use std::collections::BTreeSet;

use nucleus_node_evidence::{
    AkAnchor, AnchorPolicy, AppraisalPolicy, Divergence, ExecutorKey, Expect, Federation,
    FreshnessExpectation, ImaScope, KeyBinding, NodeEvidence, OperatorPin, Refusal,
    ReferenceManifest, Tier, appraise, evidence_digest,
};

const EVIDENCE: &str = "attested-journey-epoch8-evidence.json";
const RELEASE_REFERENCE: &str = "release-2.5.0-x86_64.node-reference.json";
/// The digest the run's signed execution receipt names.
const RECEIPT_DIGEST: &str = "880102d7208dc718c0ec41306948d7b410bd5420dcacf13898a236988212dd85";
/// The executor key the receipt was signed with.
const EXECUTOR: &str = "da9c0ad013b6f16dcf1289259941de450b9158d0d864bd992af9ed35f5e601a1";
/// The node federates (ADR 0010): SHA-256 of its JWKS at the quote.
const JWKS_SHA256: &str = "104818fd20043431085e1f81242214ca8150f3f7534526f8b26b70d61460e4f3";
const SOURCE: &str = "gcp-shielded-vm-identity:nucleus-attest-node-202610062100";
/// SHA-256 of the AK SubjectPublicKeyInfo the platform's API returned to the operator.
const PIN: &str = "0cbb90024acd17ca34b8937d4bc273621ee8f9af2f5fba7eb3811bc38051b68f";
const IAT: i64 = 1_791_322_322;
const INSTALL_DIR: &str = "/usr/local/bin";
const MODULES: &str = "/usr/lib/modules/";
const NODE_BINARIES: [&str; 3] = [
    "/usr/local/bin/nucleus-node",
    "/usr/local/bin/firecracker",
    "/usr/local/bin/jailer",
];

fn bytes(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn evidence() -> NodeEvidence {
    serde_json::from_slice(&bytes(EVIDENCE)).unwrap()
}

fn published() -> ReferenceManifest {
    serde_json::from_slice(&bytes(RELEASE_REFERENCE)).unwrap()
}

fn with_scope(mut m: ReferenceManifest, prefixes: &[&str]) -> ReferenceManifest {
    let Expect::Required(ima) = &mut m.reference_values.ima else {
        panic!("the release manifest checks IMA")
    };
    ima.scope = ImaScope::PathPrefixes(prefixes.iter().map(|p| p.to_string()).collect());
    m
}

fn release_scoped() -> ReferenceManifest {
    with_scope(published(), &[INSTALL_DIR])
}

fn hex32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

fn binding(federation: Federation) -> KeyBinding {
    KeyBinding {
        executor_key: ExecutorKey::Ed25519(hex32(EXECUTOR)),
        federation,
    }
}

fn federating() -> KeyBinding {
    binding(Federation::JwksSha256(hex32(JWKS_SHA256)))
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

fn appraise_with(
    reference: &ReferenceManifest,
    expected: &KeyBinding,
) -> Result<nucleus_node_evidence::Appraisal, Refusal> {
    appraise(
        &evidence(),
        &AppraisalPolicy {
            expected_binding: expected,
            freshness: FreshnessExpectation::Epoch {
                receipt_time: IAT + 111,
                max_age_secs: 900,
                max_future_secs: 60,
            },
            reference,
            anchors: &pinned(),
            now: IAT,
        },
    )
}

#[test]
fn the_fixture_is_the_document_the_receipt_names() {
    assert_eq!(hex::encode(evidence_digest(&bytes(EVIDENCE))), RECEIPT_DIGEST);
}

#[test]
fn before_the_published_unscoped_manifest_contests_the_platform_modules() {
    let a = appraise_with(&published(), &federating()).unwrap();
    assert_eq!(a.tier(), &Tier::Contested);
    let mut paths = Vec::new();
    for d in a.divergences() {
        match d {
            Divergence::ImaFileNotAllowed { path, .. } => paths.push(path.as_str()),
            other => panic!("only modules diverge, got {other:?}"),
        }
    }
    assert_eq!(paths.len(), 64, "the count #3276 measured");
    assert!(paths.iter().all(|p| p.starts_with(MODULES)), "{paths:?}");
    assert!(a.ima_not_in_scope().is_empty(), "no scope, nothing out of it");
}

#[test]
fn after_release_only_appraisal_is_attested_with_the_modules_named_not_in_scope() {
    let a = appraise_with(&release_scoped(), &federating()).unwrap();
    assert_eq!(a.tier(), &Tier::Attested, "{:#?}", a.divergences());
    assert_eq!(
        a.anchor(),
        &AkAnchor::OperatorFetched {
            source: SOURCE.into()
        }
    );
    // Every boot item is not checked, with the release's reason, and says so.
    assert_eq!(
        a.not_checked().keys().copied().collect::<Vec<_>>(),
        [
            "boot_files",
            "efi_applications",
            "kernel_cmdline",
            "secure_boot"
        ]
    );
    // The 64 modules are counted and named, never dropped.
    let out: Vec<&str> = a
        .ima_not_in_scope()
        .iter()
        .map(|e| e.path.as_str())
        .collect();
    assert_eq!(out.len(), 64);
    assert!(out.iter().all(|p| p.starts_with(MODULES)), "{out:?}");
    // And every in-scope measurement is one of the release's binaries.
    let quoted: BTreeSet<&str> = a
        .ima()
        .unwrap()
        .entries
        .iter()
        .map(|e| e.path.as_str())
        .filter(|p| p.starts_with("/usr/local/bin/"))
        .collect();
    assert_eq!(quoted, NODE_BINARIES.into_iter().collect());
    assert_eq!(
        a.to_ear("test", IAT)["submods"]["node"]["ear.status"],
        "affirming"
    );
}

#[test]
fn an_in_scope_binary_off_the_allowlist_is_still_contested() {
    // A-19 on the real evidence: perturb the reference (the evidence cannot be
    // edited without breaking the quote) so a measured in-scope binary is
    // unknown to it.
    for bin in ["/usr/local/bin/firecracker", "/usr/local/bin/jailer"] {
        let mut m = release_scoped();
        let Expect::Required(ima) = &mut m.reference_values.ima else {
            unreachable!()
        };
        ima.allowlist.remove(bin);
        let a = appraise_with(&m, &federating()).unwrap();
        assert_eq!(a.tier(), &Tier::Contested, "{bin}");
        assert!(
            matches!(a.divergences(), [Divergence::ImaFileNotAllowed { path, .. }] if path == bin),
            "{bin}: {:#?}",
            a.divergences()
        );
    }
    // A different release's node binary: the measured digest is not allowed.
    let mut m = release_scoped();
    let Expect::Required(ima) = &mut m.reference_values.ima else {
        unreachable!()
    };
    ima.allowlist
        .insert(NODE_BINARIES[0].into(), ["00".repeat(32)].into_iter().collect());
    let a = appraise_with(&m, &federating()).unwrap();
    assert_eq!(a.tier(), &Tier::Contested);
    assert!(a.divergences().iter().any(
        |d| matches!(d, Divergence::ImaRequiredMissing { path } if path == NODE_BINARIES[0])
    ));
}

#[test]
fn a_scope_that_takes_in_the_modules_contests_them_again() {
    let m = with_scope(published(), &[INSTALL_DIR, "/usr/lib/modules"]);
    let a = appraise_with(&m, &federating()).unwrap();
    assert_eq!(a.tier(), &Tier::Contested);
    assert_eq!(a.divergences().len(), 64);
    assert!(a.ima_not_in_scope().is_empty());
}

#[test]
fn a_federating_nodes_evidence_names_the_jwks_it_binds_when_refused() {
    let err = appraise_with(&release_scoped(), &binding(Federation::NotFederated)).unwrap_err();
    assert_eq!(
        err,
        Refusal::FederationMismatch {
            expected: Federation::NotFederated,
            bound: Federation::JwksSha256(hex32(JWKS_SHA256)),
        }
    );
    assert!(err.to_string().contains(JWKS_SHA256), "{err}");
    // Another executor key is a different refusal, named as such.
    let other = KeyBinding {
        executor_key: ExecutorKey::Ed25519([0; 32]),
        federation: Federation::JwksSha256(hex32(JWKS_SHA256)),
    };
    assert_eq!(
        appraise_with(&release_scoped(), &other).unwrap_err(),
        Refusal::ExecutorKeyMismatch
    );
}
