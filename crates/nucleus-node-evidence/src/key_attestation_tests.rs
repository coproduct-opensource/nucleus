//! Federation-key custody against a software TPM: an honest certification is
//! shown `TpmBound` first, then every refusal is driven from it by one
//! perturbation (A-19). The real-TPM round trip is
//! `tests/federation_key_swtpm.rs`.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use p256::ecdsa::SigningKey;

use crate::anchor::AkAnchorClaim;
use crate::appraise::{AppraisalPolicy, Refusal, Tier};
use crate::appraise_tests::{
    SOURCE, ak, binding, challenge, honest_boot, node_quoting, nonce, pinned, reference,
};
use crate::binding::{ExecutorKey, Freshness, KeyBinding};
use crate::crypto::sha256;
use crate::evidence::NodeEvidence;
use crate::key_attestation::{
    ADMIN_WITH_POLICY, AttestedKey, BOOT_POLICY_PCRS, CustodyStatement, DECRYPT,
    FEDERATION_KEY_ATTRIBUTES, FIXED_PARENT, FIXED_TPM, FederationKeyAttestation,
    KEY_ATTESTATION_PROFILE, KeyRefusal, KeyResidency, RESTRICTED, SENSITIVE_DATA_ORIGIN, SIGN,
    TpmCustodyStatement, USER_WITH_AUTH, appraise_federation_keys, boot_policy_pcrs,
    certify_qualifying_data, object_name, policy_pcr_digest,
};
use crate::tpm::build;

const KID: &str = "federation-key-1";
const TPM_RH_OWNER: u32 = 0x4000_0001;
const TPM_RH_NULL: u32 = 0x4000_0007;

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn b64url(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn tpm2b(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&u16::try_from(b.len()).unwrap().to_be_bytes());
    out.extend_from_slice(b);
}

/// Evidence quoting every boot PCR the policy names (2 and 14 as firmware
/// leaves them on a machine with no option ROMs or MOK).
fn evidence() -> NodeEvidence {
    node_quoting(
        &honest_boot(),
        &ak(),
        &binding(),
        Freshness::Challenge {
            eat_nonce: nonce(1),
        },
        AkAnchorClaim::OperatorFetched {
            source: SOURCE.into(),
        },
        &[(2, [0u8; 32]), (14, [0u8; 32])],
    )
}

fn quoted(e: &NodeEvidence) -> BTreeMap<u8, [u8; 32]> {
    e.tpm
        .pcrs
        .iter()
        .map(|(k, v)| (*k, hex::decode(v).unwrap().try_into().unwrap()))
        .collect()
}

fn point(sk: &SigningKey) -> ([u8; 32], [u8; 32]) {
    let p = sk.verifying_key().to_encoded_point(false);
    (
        p.x().unwrap().as_slice().try_into().unwrap(),
        p.y().unwrap().as_slice().try_into().unwrap(),
    )
}

/// A `TPMT_PUBLIC` for an ECC P-256 key.
fn tpmt(attributes: u32, policy: &[u8], storage: bool, xy: ([u8; 32], [u8; 32])) -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(&0x0023u16.to_be_bytes()); // ECC
    t.extend_from_slice(&0x000Bu16.to_be_bytes()); // nameAlg SHA-256
    t.extend_from_slice(&attributes.to_be_bytes());
    tpm2b(&mut t, policy);
    if storage {
        t.extend_from_slice(&0x0006u16.to_be_bytes()); // AES
        t.extend_from_slice(&128u16.to_be_bytes());
        t.extend_from_slice(&0x0043u16.to_be_bytes()); // CFB
        t.extend_from_slice(&0x0010u16.to_be_bytes()); // scheme NULL
    } else {
        t.extend_from_slice(&0x0010u16.to_be_bytes()); // symmetric NULL
        t.extend_from_slice(&0x0018u16.to_be_bytes()); // ECDSA
        t.extend_from_slice(&0x000Bu16.to_be_bytes()); // SHA-256
    }
    t.extend_from_slice(&0x0003u16.to_be_bytes()); // P-256
    t.extend_from_slice(&0x0010u16.to_be_bytes()); // kdf NULL
    tpm2b(&mut t, &xy.0);
    tpm2b(&mut t, &xy.1);
    t
}

fn tpm2b_of(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    tpm2b(&mut out, b);
    out
}

fn qualified(parent_qn: &[u8], name: &[u8]) -> Vec<u8> {
    let mut buf = parent_qn.to_vec();
    buf.extend_from_slice(name);
    let mut out = 0x000Bu16.to_be_bytes().to_vec();
    out.extend_from_slice(&sha256(&buf));
    out
}

/// The software TPM's side: a key, its parent, and an AK-signed certify.
struct Made {
    key: SigningKey,
    public: Vec<u8>,
    parent_public: Vec<u8>,
    attest: Vec<u8>,
}

fn certify_attest(extra: &[u8], name: &[u8], qualified_name: &[u8]) -> Vec<u8> {
    let mut a = Vec::new();
    a.extend_from_slice(&0xff54_4347u32.to_be_bytes());
    a.extend_from_slice(&0x8017u16.to_be_bytes());
    tpm2b(&mut a, b"\x00\x0bsigner");
    tpm2b(&mut a, extra);
    a.extend_from_slice(&1234u64.to_be_bytes());
    a.extend_from_slice(&3u32.to_be_bytes());
    a.extend_from_slice(&0u32.to_be_bytes());
    a.push(1);
    a.extend_from_slice(&42u64.to_be_bytes());
    tpm2b(&mut a, name);
    tpm2b(&mut a, qualified_name);
    a
}

/// What a TPM produces for a key with `attributes` and `policy`, under the
/// owner hierarchy (or `hierarchy`).
fn make_with(attributes: u32, policy: &[u8; 32], hierarchy: u32) -> Made {
    let key = SigningKey::from_slice(&[0x33; 32]).unwrap();
    let parent = SigningKey::from_slice(&[0x44; 32]).unwrap();
    let key_tpmt = tpmt(attributes, policy, false, point(&key));
    let parent_tpmt = tpmt(0x0003_0472, &[], true, point(&parent));
    let parent_qn = qualified(&hierarchy.to_be_bytes(), &object_name(&parent_tpmt));
    let qn = qualified(&parent_qn, &object_name(&key_tpmt));
    let attest = certify_attest(&certify_qualifying_data(), &object_name(&key_tpmt), &qn);
    Made {
        key,
        public: tpm2b_of(&key_tpmt),
        parent_public: tpm2b_of(&parent_tpmt),
        attest,
    }
}

fn honest_policy(e: &NodeEvidence) -> [u8; 32] {
    policy_pcr_digest(&boot_policy_pcrs(), &quoted(e)).unwrap()
}

fn statement(m: &Made, signer: &SigningKey) -> TpmCustodyStatement {
    TpmCustodyStatement {
        public: b64(&m.public),
        parent_public: b64(&m.parent_public),
        policy_pcrs: boot_policy_pcrs(),
        certify_attest: b64(&m.attest),
        certify_signature: b64(&build::sign(signer, &m.attest)),
    }
}

fn doc(custody: CustodyStatement) -> FederationKeyAttestation {
    FederationKeyAttestation {
        profile: KEY_ATTESTATION_PROFILE.into(),
        keys: vec![AttestedKey {
            kid: KID.into(),
            custody,
        }],
    }
}

fn jwks_of(sk: &SigningKey) -> serde_json::Value {
    let (x, y) = point(sk);
    serde_json::json!({ "keys": [{
        "kty": "EC", "crv": "P-256", "x": b64url(&x), "y": b64url(&y),
        "kid": KID, "alg": "ES256", "use": "sig"
    }]})
}

fn check_with(
    e: &NodeEvidence,
    bind: &KeyBinding,
    jwks: &serde_json::Value,
    d: &FederationKeyAttestation,
) -> Result<(Tier, Vec<KeyResidency>), KeyRefusal> {
    let r = reference();
    let anchors = pinned();
    appraise_federation_keys(
        e,
        &AppraisalPolicy {
            expected_binding: bind,
            freshness: challenge(1),
            reference: &r,
            anchors: &anchors,
            now: crate::appraise_tests::NOW,
        },
        jwks,
        d,
    )
    .map(|(a, v)| (a.tier().clone(), v))
}

fn check(
    jwks: &serde_json::Value,
    d: &FederationKeyAttestation,
) -> Result<(Tier, Vec<KeyResidency>), KeyRefusal> {
    check_with(&evidence(), &binding(), jwks, d)
}

fn honest() -> (Made, TpmCustodyStatement) {
    let e = evidence();
    let m = make_with(FEDERATION_KEY_ATTRIBUTES, &honest_policy(&e), TPM_RH_OWNER);
    let s = statement(&m, &ak());
    (m, s)
}

fn refusal(r: Result<(Tier, Vec<KeyResidency>), KeyRefusal>) -> KeyRefusal {
    r.expect_err("refused")
}

// ---------------------------------------------------------------- baseline

#[test]
fn an_honest_certification_is_tpm_bound_on_an_attested_boot() {
    let (m, s) = honest();
    let (tier, verdicts) = check(&jwks_of(&m.key), &doc(CustodyStatement::Tpm(s))).unwrap();
    assert_eq!(tier, Tier::Attested);
    assert_eq!(verdicts.len(), 1);
    assert!(verdicts[0].is_tpm_bound(), "{verdicts:?}");
    let KeyResidency::TpmBound {
        kid, policy_pcrs, ..
    } = &verdicts[0]
    else {
        unreachable!()
    };
    assert_eq!(kid, KID);
    assert_eq!(policy_pcrs, &BOOT_POLICY_PCRS.into_iter().collect());
}

#[test]
fn the_attestation_document_round_trips_through_json() {
    let (_, s) = honest();
    let d = doc(CustodyStatement::Tpm(s));
    let back: FederationKeyAttestation =
        serde_json::from_slice(&serde_json::to_vec(&d).unwrap()).unwrap();
    assert_eq!(back, d);
}

// ----------------------------------------------------- honest non-passes

#[test]
fn a_file_key_is_not_tpm_resident_and_never_a_pass() {
    let (m, _) = honest();
    let d = doc(CustodyStatement::File {
        reason: "waived by the operator".into(),
    });
    let (_, verdicts) = check(&jwks_of(&m.key), &d).unwrap();
    assert_eq!(
        verdicts,
        vec![KeyResidency::NotTpmResident {
            kid: KID.into(),
            reason: "waived by the operator".into()
        }]
    );
    assert!(!verdicts[0].is_tpm_bound());
}

#[test]
fn a_key_with_no_statement_is_unstated_not_a_pass() {
    let (m, _) = honest();
    let d = FederationKeyAttestation {
        profile: KEY_ATTESTATION_PROFILE.into(),
        keys: vec![],
    };
    let (_, verdicts) = check(&jwks_of(&m.key), &d).unwrap();
    assert_eq!(verdicts, vec![KeyResidency::Unstated { kid: KID.into() }]);
    assert!(!verdicts[0].is_tpm_bound());
}

// ---------------------------------------------------------------- refusals

#[test]
fn a_certification_signed_by_another_key_is_refused() {
    let (m, _) = honest();
    let other = SigningKey::from_slice(&[0x99; 32]).unwrap();
    let s = statement(&m, &other);
    assert!(matches!(
        refusal(check(&jwks_of(&m.key), &doc(CustodyStatement::Tpm(s)))),
        KeyRefusal::CertifySignature { .. }
    ));
}

#[test]
fn a_rewritten_auth_policy_breaks_the_certified_name() {
    // The Name covers the authPolicy: publishing the certified key with a
    // different policy digest (here, a policy over nothing) is refused.
    let (m, mut s) = honest();
    let mut public = m.public.clone();
    // TPM2B size (2) + type (2) + nameAlg (2) + attributes (4) + policy size (2).
    public[12] ^= 0x01;
    s.public = b64(&public);
    assert!(matches!(
        refusal(check(&jwks_of(&m.key), &doc(CustodyStatement::Tpm(s)))),
        KeyRefusal::NameMismatch { .. }
    ));
}

#[test]
fn another_keys_public_area_under_this_certification_is_refused() {
    let (_, mut s) = honest();
    let other_key = SigningKey::from_slice(&[0x35; 32]).unwrap();
    s.public = b64(&tpm2b_of(&tpmt(
        FEDERATION_KEY_ATTRIBUTES,
        &honest_policy(&evidence()),
        false,
        point(&other_key),
    )));
    assert!(matches!(
        refusal(check(&jwks_of(&other_key), &doc(CustodyStatement::Tpm(s)))),
        KeyRefusal::NameMismatch { .. }
    ));
}

#[test]
fn a_certified_key_that_is_not_the_jwks_key_is_refused() {
    let (_, s) = honest();
    let stranger = SigningKey::from_slice(&[0x36; 32]).unwrap();
    assert!(matches!(
        refusal(check(&jwks_of(&stranger), &doc(CustodyStatement::Tpm(s)))),
        KeyRefusal::JwkMismatch { .. }
    ));
}

#[test]
fn a_key_the_empty_password_can_use_is_refused() {
    let e = evidence();
    for (attrs, needle) in [
        (FEDERATION_KEY_ATTRIBUTES | USER_WITH_AUTH, "userWithAuth"),
        (
            FEDERATION_KEY_ATTRIBUTES | ADMIN_WITH_POLICY,
            "adminWithPolicy",
        ),
        (FEDERATION_KEY_ATTRIBUTES & !FIXED_TPM, "fixedTPM"),
        (FEDERATION_KEY_ATTRIBUTES & !FIXED_PARENT, "fixedParent"),
        (
            FEDERATION_KEY_ATTRIBUTES & !SENSITIVE_DATA_ORIGIN,
            "sensitiveDataOrigin",
        ),
        (FEDERATION_KEY_ATTRIBUTES & !SIGN, "sign"),
        (FEDERATION_KEY_ATTRIBUTES | DECRYPT, "decrypt"),
        (FEDERATION_KEY_ATTRIBUTES | RESTRICTED, "restricted"),
    ] {
        let m = make_with(attrs, &honest_policy(&e), TPM_RH_OWNER);
        let s = statement(&m, &ak());
        match refusal(check(&jwks_of(&m.key), &doc(CustodyStatement::Tpm(s)))) {
            KeyRefusal::KeyAttributes { problems, .. } => {
                assert!(problems.iter().any(|p| p.contains(needle)), "{problems:?}");
            }
            other => panic!("{needle}: {other:?}"),
        }
    }
}

#[test]
fn a_key_bound_to_another_boot_state_is_refused() {
    // Honestly certified, but its policy is over a PCR 8 (command line) that
    // is not the quoted one: it signs only in some other boot.
    let e = evidence();
    let mut other_boot = quoted(&e);
    other_boot.insert(8, [0x08; 32]);
    let policy = policy_pcr_digest(&boot_policy_pcrs(), &other_boot).unwrap();
    let m = make_with(FEDERATION_KEY_ATTRIBUTES, &policy, TPM_RH_OWNER);
    let s = statement(&m, &ak());
    assert!(matches!(
        refusal(check(&jwks_of(&m.key), &doc(CustodyStatement::Tpm(s)))),
        KeyRefusal::PolicyMismatch { .. }
    ));
}

#[test]
fn a_policy_that_leaves_out_a_boot_pcr_is_refused() {
    // Bound to every boot PCR but 14 — honestly, with the digest to match.
    let e = evidence();
    let narrow: BTreeSet<u8> = [0, 2, 4, 7, 8, 9].into_iter().collect();
    let m = make_with(
        FEDERATION_KEY_ATTRIBUTES,
        &policy_pcr_digest(&narrow, &quoted(&e)).unwrap(),
        TPM_RH_OWNER,
    );
    let mut s = statement(&m, &ak());
    s.policy_pcrs = narrow;
    match refusal(check(&jwks_of(&m.key), &doc(CustodyStatement::Tpm(s)))) {
        KeyRefusal::PolicyTooNarrow { missing, .. } => {
            assert_eq!(missing, [14].into_iter().collect())
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn restating_the_policy_pcrs_without_the_digest_is_refused() {
    // The statement's PCR list is a claim; the digest in the certified area
    // decides. Claiming one more PCR than the key was bound to does not
    // reach the certified digest.
    let (m, mut s) = honest();
    s.policy_pcrs.insert(10);
    assert!(matches!(
        refusal(check(&jwks_of(&m.key), &doc(CustodyStatement::Tpm(s)))),
        KeyRefusal::PolicyMismatch { .. }
    ));
}

#[test]
fn a_policy_over_an_unquoted_pcr_is_refused() {
    let (m, mut s) = honest();
    s.policy_pcrs.insert(16);
    match refusal(check(&jwks_of(&m.key), &doc(CustodyStatement::Tpm(s)))) {
        KeyRefusal::PolicyNotQuoted { missing, .. } => {
            assert_eq!(missing, [16].into_iter().collect())
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_key_outside_the_owner_hierarchy_is_refused() {
    // The NULL hierarchy is where an external, software-made public area
    // would be loaded.
    let e = evidence();
    let m = make_with(FEDERATION_KEY_ATTRIBUTES, &honest_policy(&e), TPM_RH_NULL);
    let s = statement(&m, &ak());
    assert!(matches!(
        refusal(check(&jwks_of(&m.key), &doc(CustodyStatement::Tpm(s)))),
        KeyRefusal::QualifiedNameMismatch { .. }
    ));
}

#[test]
fn a_parent_that_is_not_a_storage_key_is_refused() {
    let (m, mut s) = honest();
    let parent = SigningKey::from_slice(&[0x44; 32]).unwrap();
    s.parent_public = b64(&tpm2b_of(&tpmt(
        FEDERATION_KEY_ATTRIBUTES,
        &[],
        false,
        point(&parent),
    )));
    assert!(matches!(
        refusal(check(&jwks_of(&m.key), &doc(CustodyStatement::Tpm(s)))),
        KeyRefusal::ParentAttributes { .. }
    ));
}

#[test]
fn a_certification_for_another_purpose_is_refused() {
    let e = evidence();
    let mut m = make_with(FEDERATION_KEY_ATTRIBUTES, &honest_policy(&e), TPM_RH_OWNER);
    let key_tpmt = &m.public[2..];
    let parent_qn = qualified(
        &TPM_RH_OWNER.to_be_bytes(),
        &object_name(&m.parent_public[2..]),
    );
    m.attest = certify_attest(
        b"another purpose",
        &object_name(key_tpmt),
        &qualified(&parent_qn, &object_name(key_tpmt)),
    );
    let s = statement(&m, &ak());
    assert!(matches!(
        refusal(check(&jwks_of(&m.key), &doc(CustodyStatement::Tpm(s)))),
        KeyRefusal::QualifyingData { .. }
    ));
}

#[test]
fn a_quote_is_not_a_certification() {
    let (m, mut s) = honest();
    let pcrs: BTreeSet<u8> = [0].into_iter().collect();
    let quote = build::quote(&certify_qualifying_data(), &pcrs, &[0u8; 32]);
    s.certify_attest = b64(&quote);
    s.certify_signature = b64(&build::sign(&ak(), &quote));
    assert!(matches!(
        refusal(check(&jwks_of(&m.key), &doc(CustodyStatement::Tpm(s)))),
        KeyRefusal::Malformed(_)
    ));
}

#[test]
fn refused_evidence_vouches_for_no_key() {
    let (m, s) = honest();
    let other = KeyBinding {
        executor_key: ExecutorKey::Ed25519([0xE1; 32]),
        ..binding()
    };
    assert!(matches!(
        refusal(check_with(
            &evidence(),
            &other,
            &jwks_of(&m.key),
            &doc(CustodyStatement::Tpm(s))
        )),
        KeyRefusal::Evidence(Refusal::ExecutorKeyMismatch)
    ));
}

#[test]
fn an_unknown_profile_is_refused() {
    let (m, s) = honest();
    let mut d = doc(CustodyStatement::Tpm(s));
    d.profile = "nucleus-federation-key-attestation/v0".into();
    assert!(matches!(
        refusal(check(&jwks_of(&m.key), &d)),
        KeyRefusal::UnknownProfile(_)
    ));
}
