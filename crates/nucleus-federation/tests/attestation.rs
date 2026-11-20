//! ADR 0012 A3: the assertion states the node's platform tier and names the
//! evidence epoch it rests on, a relying party's verifier checks the claim
//! against that evidence, and the documented attribute condition, evaluated
//! by a CEL implementation, refuses everything but a fresh `attested`.
//!
//! The evidence is real: the epoch-4 document a cloud vTPM node produced in
//! the #2706 live run (`nucleus-node-evidence/tests/fixtures`), with the AK
//! pin the provider's API reported for that VM.

use std::collections::HashMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use nucleus_federation::{
    ATTESTATION_CLAIMS, AssertionClaims, AssertionSubject, ClaimRefusal, ClaimedTier, DEFAULT_TTL,
    EPOCH_CLAIM, EVIDENCE_CLAIM, EcdsaP256Signer, EvidenceRef, ExternalIssuerConfig,
    ExternalIssuerValidator, HeldEvidence, JwksSource, NO_EVIDENCE, NodeAttestation,
    RELYING_PARTY_CONDITION, Reappraisal, RelyingPartyCheck, SelfAppraisal, TIER_CLAIM, TIME_CLAIM,
    VerifyAlg, mint, relying_party_condition_for, verify_attestation_claims,
};
use nucleus_node_evidence::{
    AnchorPolicy, ExecutorKey, Federation, KeyBinding, OperatorPin, ReferenceManifest,
};
use serde_json::{Map, Value, json};

/// The executor key the epoch-4 evidence is bound to.
const EXECUTOR: &str = "929fbe08d9cbaec3659c5ac626e31bec8065107461fe77aa3b4af1c4f230be85";
/// SHA-256 of the AK SubjectPublicKeyInfo the provider's API reported.
const PIN: &str = "beced81752041938278acd53c5df51df98652f58bb76bdf722e8965d25bd2366";
/// SHA-256 of the epoch-4 document (the digest the live run's receipt named).
const EPOCH4_DIGEST: &str = "d0689ce45219cf0e9e7827e0988c00a0a8545df93f773339734d92f44837bcab";
/// The epoch-4 quote's time.
const QUOTED_AT: i64 = 1_791_247_232;
/// A mint thirty seconds into the epoch.
const MINT: i64 = QUOTED_AT + 30;
/// The node's re-quote interval in these tests: the default.
const EPOCH_SECS: u64 = 300;
const ISSUER: &str = "https://federation.nodes.example.invalid";
const AUDIENCE: &str = "https://sts.example.invalid/provider";

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/../nucleus-node-evidence/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn evidence() -> Vec<u8> {
    fixture("live-node-epoch4-evidence.json")
}

fn binding() -> KeyBinding {
    KeyBinding {
        executor_key: ExecutorKey::Ed25519(hex::decode(EXECUTOR).unwrap().try_into().unwrap()),
        federation: Federation::NotFederated,
    }
}

/// The anchor source the evidence claims, read from the evidence rather than
/// restated here.
fn source() -> String {
    let doc: Value = serde_json::from_slice(&evidence()).unwrap();
    doc["ak_anchor"]["operator_fetched"]["source"]
        .as_str()
        .unwrap()
        .to_string()
}

fn anchors(pinned: bool) -> AnchorPolicy {
    AnchorPolicy {
        software_tpm_pins: Vec::new(),
        trust_roots: vec![],
        operator_pins: if pinned {
            vec![OperatorPin {
                source: source(),
                ak_spki_sha256: PIN.into(),
            }]
        } else {
            vec![]
        },
    }
}

fn reference() -> ReferenceManifest {
    serde_json::from_slice(&fixture("live-node-reference-exact.json")).unwrap()
}

/// The exact reference with one kernel parameter the node did not boot with:
/// the same evidence appraises `contested` under it.
fn contested_reference() -> ReferenceManifest {
    let mut doc: Value =
        serde_json::from_slice(&fixture("live-node-reference-exact.json")).unwrap();
    doc["reference-values"]["kernel_cmdline"]["required"]["exact_params"]
        .as_array_mut()
        .unwrap()
        .push("nucleus.expected=1".into());
    serde_json::from_value(doc).unwrap()
}

/// The node's own appraisal at `now`, under the given inputs.
fn appraised(reference: &ReferenceManifest, pinned: bool, now: i64) -> NodeAttestation {
    let b = binding();
    let a = anchors(pinned);
    NodeAttestation::of_current_evidence(
        &evidence(),
        Some(&SelfAppraisal {
            binding: &b,
            reference,
            anchors: &a,
            max_age_secs: SelfAppraisal::max_age_for_epoch(EPOCH_SECS),
        }),
        now,
    )
}

fn signer() -> EcdsaP256Signer {
    EcdsaP256Signer::from_pkcs8(&EcdsaP256Signer::generate_pkcs8().unwrap()).unwrap()
}

fn subject() -> AssertionSubject {
    AssertionSubject::new(
        "spiffe://nodes.example.invalid/ns/pods/sa/pod-a",
        "tenant-a.example.invalid",
        "spiffe://tenant-a.example.invalid/ns/ci/sa/release",
        "ab".repeat(32),
    )
    .unwrap()
}

/// Mint a real assertion and return its compact form and decoded payload.
fn mint_at(
    att: &NodeAttestation,
    now: i64,
    signer: &EcdsaP256Signer,
) -> (String, Map<String, Value>) {
    let claims = AssertionClaims::new(
        &subject(),
        ISSUER,
        AUDIENCE,
        "model-api",
        u64::try_from(now).unwrap(),
        DEFAULT_TTL,
        att,
    )
    .unwrap();
    assert_eq!(claims.attestation_tier(), att.tier());
    let jwt = mint(&claims, signer).unwrap();
    let payload = jwt.expose().split('.').nth(1).unwrap();
    let payload: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
    (
        jwt.expose().to_string(),
        payload.as_object().unwrap().clone(),
    )
}

fn payload(att: &NodeAttestation, now: i64) -> Map<String, Value> {
    mint_at(att, now, &signer()).1
}

// ── The node's statement ────────────────────────────────────────────────────

/// An appraised node states `attested` and names the epoch it appraised: the
/// counter, the quote time, and the digest a relying party fetches it by.
#[test]
fn an_appraised_node_states_attested_and_names_its_epoch() {
    let att = appraised(&reference(), true, MINT);
    assert_eq!(att.tier(), ClaimedTier::Attested, "{}", att.note());
    let p = payload(&att, MINT);
    assert_eq!(p[TIER_CLAIM], "attested");
    assert_eq!(p[EPOCH_CLAIM], "4");
    assert_eq!(p[TIME_CLAIM], QUOTED_AT.to_string());
    assert_eq!(p[EVIDENCE_CLAIM], EPOCH4_DIGEST);
}

/// "Could not look" is never "attested": every way the node cannot vouch for
/// its platform states `unattested` (or the tier the appraisal found), and
/// none of them states `attested`.
#[test]
fn a_node_that_cannot_vouch_states_unattested_never_attested() {
    let b = binding();
    let a = anchors(true);
    let r = reference();
    let inputs = SelfAppraisal {
        binding: &b,
        reference: &r,
        anchors: &a,
        max_age_secs: SelfAppraisal::max_age_for_epoch(EPOCH_SECS),
    };
    // No TPM attester.
    let none = NodeAttestation::without_evidence("no TPM attester configured");
    assert_eq!(none.tier(), ClaimedTier::Unattested);
    assert_eq!(none.evidence(), &EvidenceRef::NoEvidence);
    // No reference to appraise against: names the evidence, states unattested.
    let unappraised = NodeAttestation::of_current_evidence(&evidence(), None, MINT);
    assert_eq!(unappraised.tier(), ClaimedTier::Unattested);
    assert!(matches!(unappraised.evidence(), EvidenceRef::Epoch(e) if e.counter == 4));
    // No pin for the AK.
    assert_eq!(appraised(&r, false, MINT).tier(), ClaimedTier::Unattested);
    // A document that is not evidence, and evidence that is not epoch evidence.
    let garbage = NodeAttestation::of_current_evidence(b"{}", Some(&inputs), MINT);
    assert_eq!(garbage.tier(), ClaimedTier::Unattested);
    assert_eq!(garbage.evidence(), &EvidenceRef::NoEvidence);
    let challenge = NodeAttestation::of_current_evidence(
        &fixture("live-node-perturbed-challenge-evidence.json"),
        Some(&inputs),
        MINT,
    );
    assert_eq!(challenge.tier(), ClaimedTier::Unattested);
    // Evidence bound to another executor key is refused: unattested.
    let other = KeyBinding {
        executor_key: ExecutorKey::Ed25519([7; 32]),
        federation: Federation::NotFederated,
    };
    let refused = NodeAttestation::of_current_evidence(
        &evidence(),
        Some(&SelfAppraisal {
            binding: &other,
            reference: &r,
            anchors: &a,
            max_age_secs: SelfAppraisal::max_age_for_epoch(EPOCH_SECS),
        }),
        MINT,
    );
    assert_eq!(
        refused.tier(),
        ClaimedTier::Unattested,
        "{}",
        refused.note()
    );
    // Diverging measurements.
    assert_eq!(
        appraised(&contested_reference(), true, MINT).tier(),
        ClaimedTier::Contested
    );
}

/// The node's own bound: evidence older than one epoch plus the grace at the
/// mint time is `expired`, never `attested` — whatever else is true of it.
#[test]
fn evidence_older_than_one_epoch_is_expired_at_the_node() {
    let limit = i64::try_from(SelfAppraisal::max_age_for_epoch(EPOCH_SECS)).unwrap();
    assert_eq!(
        appraised(&reference(), true, QUOTED_AT + limit).tier(),
        ClaimedTier::Attested
    );
    assert_eq!(
        appraised(&reference(), true, QUOTED_AT + limit + 1).tier(),
        ClaimedTier::Expired
    );
}

/// The four claims are on every assertion, as strings, under their published
/// names, whatever the node could say about its platform.
#[test]
fn the_attestation_claims_are_never_omitted() {
    for att in [
        appraised(&reference(), true, MINT),
        appraised(&reference(), false, MINT),
        appraised(&contested_reference(), true, MINT),
        appraised(&reference(), true, MINT + 3600),
        NodeAttestation::of_current_evidence(&evidence(), None, MINT),
        NodeAttestation::without_evidence("no TPM"),
    ] {
        let p = payload(&att, MINT);
        for claim in ATTESTATION_CLAIMS {
            assert!(
                p.get(claim).is_some_and(Value::is_string),
                "{claim} missing or not a string for {}: {p:?}",
                att.tier()
            );
        }
        assert_eq!(p[TIER_CLAIM], att.tier().as_str());
    }
    let p = payload(&NodeAttestation::without_evidence("no TPM"), MINT);
    for claim in [EPOCH_CLAIM, TIME_CLAIM, EVIDENCE_CLAIM] {
        assert_eq!(p[claim], NO_EVIDENCE);
    }
}

// ── The relying party's verifier ────────────────────────────────────────────

fn claim_only(now: i64) -> RelyingPartyCheck<'static> {
    RelyingPartyCheck {
        now,
        max_age_secs: 900,
        reappraisal: Reappraisal::ClaimOnly,
    }
}

/// A stale epoch is refused, and so is one from the future, though the
/// assertion itself says `attested` and was honestly minted.
#[test]
fn the_verifier_refuses_a_stale_epoch() {
    let p = payload(&appraised(&reference(), true, MINT), MINT);
    let ok = verify_attestation_claims(&p, &claim_only(QUOTED_AT + 900)).unwrap();
    assert_eq!(ok.tier, ClaimedTier::Attested);
    assert_eq!(
        verify_attestation_claims(&p, &claim_only(QUOTED_AT + 901)),
        Err(ClaimRefusal::Stale {
            age_secs: 901,
            max_age_secs: 900
        })
    );
    assert_eq!(
        verify_attestation_claims(&p, &claim_only(QUOTED_AT - 61)),
        Err(ClaimRefusal::FromTheFuture { ahead_secs: 61 })
    );
}

/// Re-appraisal: the claim must be what the relying party's own appraisal of
/// the named evidence finds. An honest claim passes; a claim the evidence
/// does not support is refused, in either direction; evidence that is not the
/// named document is refused.
#[test]
fn the_verifier_refuses_a_tier_the_evidence_does_not_support() {
    let doc = evidence();
    let pinned = anchors(true);
    let unpinned = anchors(false);
    let exact = reference();
    let contested = contested_reference();
    fn check(
        reference: &ReferenceManifest,
        anchors: &AnchorPolicy,
        document: &[u8],
        p: &Map<String, Value>,
    ) -> Result<nucleus_federation::VerifiedAttestation, ClaimRefusal> {
        let b = binding();
        let held = HeldEvidence {
            document,
            binding: &b,
            reference,
            anchors,
        };
        let check = RelyingPartyCheck {
            now: MINT + 10,
            max_age_secs: 900,
            reappraisal: Reappraisal::Evidence(held),
        };
        verify_attestation_claims(p, &check)
    }

    let attested = payload(&appraised(&exact, true, MINT), MINT);
    // Honest: the relying party finds what the node said.
    let ok = check(&exact, &pinned, &doc, &attested).unwrap();
    assert_eq!(ok.reappraised, Some(ClaimedTier::Attested));
    // The relying party's reference says contested.
    assert_eq!(
        check(&contested, &pinned, &doc, &attested),
        Err(ClaimRefusal::TierMismatch {
            claimed: ClaimedTier::Attested,
            appraised: ClaimedTier::Contested
        })
    );
    // The relying party does not anchor this AK.
    assert_eq!(
        check(&exact, &unpinned, &doc, &attested),
        Err(ClaimRefusal::TierMismatch {
            claimed: ClaimedTier::Attested,
            appraised: ClaimedTier::Unattested
        })
    );
    // The node said contested; the evidence appraises attested.
    let said_contested = payload(&appraised(&contested, true, MINT), MINT);
    assert_eq!(
        check(&exact, &pinned, &doc, &said_contested),
        Err(ClaimRefusal::TierMismatch {
            claimed: ClaimedTier::Contested,
            appraised: ClaimedTier::Attested
        })
    );
    // A node that did not look is never contradicted: unattested is no claim.
    let unappraised = payload(
        &NodeAttestation::of_current_evidence(&doc, None, MINT),
        MINT,
    );
    let ok = check(&exact, &pinned, &doc, &unappraised).unwrap();
    assert_eq!(ok.tier, ClaimedTier::Unattested);
    // A tier rewritten on the claims (as a key holder could sign) is caught.
    let mut forged = payload(&appraised(&exact, false, MINT), MINT);
    assert_eq!(forged[TIER_CLAIM], "unattested");
    forged.insert(TIER_CLAIM.into(), "attested".into());
    assert_eq!(
        check(&exact, &unpinned, &doc, &forged),
        Err(ClaimRefusal::TierMismatch {
            claimed: ClaimedTier::Attested,
            appraised: ClaimedTier::Unattested
        })
    );
    // Other bytes than the named document.
    let other = fixture("vtpm-epoch-evidence.json");
    assert_eq!(
        check(&exact, &pinned, &other, &attested),
        Err(ClaimRefusal::EvidenceDigest)
    );
    // The right document, the wrong epoch claimed for it.
    let mut wrong_epoch = attested.clone();
    wrong_epoch.insert(EPOCH_CLAIM.into(), "5".into());
    assert_eq!(
        check(&exact, &pinned, &doc, &wrong_epoch),
        Err(ClaimRefusal::EpochMismatch)
    );
}

/// An omitted claim is refused by name, never read as `unattested` or as a
/// pass; a half-named epoch and a tier that names nothing are refused too.
#[test]
fn an_omitted_claim_is_refused_not_read_as_a_value() {
    let p = payload(&appraised(&reference(), true, MINT), MINT);
    for claim in ATTESTATION_CLAIMS {
        let mut without = p.clone();
        without.remove(claim);
        assert_eq!(
            verify_attestation_claims(&without, &claim_only(MINT)),
            Err(ClaimRefusal::Omitted(claim))
        );
    }
    let mut partial = p.clone();
    partial.insert(EVIDENCE_CLAIM.into(), NO_EVIDENCE.into());
    assert_eq!(
        verify_attestation_claims(&partial, &claim_only(MINT)),
        Err(ClaimRefusal::PartialEvidence)
    );
    let mut bare = payload(&NodeAttestation::without_evidence("x"), MINT);
    bare.insert(TIER_CLAIM.into(), "attested".into());
    assert_eq!(
        verify_attestation_claims(&bare, &claim_only(MINT)),
        Err(ClaimRefusal::TierWithoutEvidence(ClaimedTier::Attested))
    );
    let mut odd = p.clone();
    odd.insert(TIER_CLAIM.into(), "Attested".into());
    assert_eq!(
        verify_attestation_claims(&odd, &claim_only(MINT)),
        Err(ClaimRefusal::Malformed(TIER_CLAIM))
    );
}

/// In composition: the assertion a node signs, validated the way a relying
/// party running this crate would (signature, `iss`, `aud`, `exp` by the
/// inbound validator), then its platform claims re-appraised.
#[tokio::test]
async fn a_signed_assertion_verifies_end_to_end() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let s = signer();
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    // The live evidence is from a fixed time; the validator checks `exp`
    // against the wall clock. Mint now, and re-appraise at the assertion's
    // iat: the fixture is then stale, which is the point of this test's
    // second half.
    let att = appraised(&reference(), true, MINT);
    let (compact, _) = mint_at(&att, now, &s);
    let validator = ExternalIssuerValidator::new(
        ExternalIssuerConfig::new(
            ISSUER,
            AUDIENCE,
            [VerifyAlg::Es256],
            JwksSource::Inline(serde_json::from_value(s.jwks()).unwrap()),
        ),
        nucleus_federation::default_client().unwrap(),
    )
    .unwrap();
    let caller = validator
        .validate(&compact, u64::try_from(now).unwrap())
        .await
        .unwrap();
    assert_eq!(caller.claims[TIER_CLAIM], "attested");
    // The evidence the claim names is a year old by now: refused as stale,
    // though the signature, issuer and audience are all good.
    assert!(matches!(
        verify_attestation_claims(&caller.claims, &claim_only(now)),
        Err(ClaimRefusal::Stale { .. })
    ));
}

// ── The relying party's attribute condition, evaluated by CEL ───────────────

/// A JSON value as a provider that evaluates CEL over a decoded token sees
/// it: a JSON object becomes a map, and every JSON number a double (the
/// `google.protobuf.Struct` reading of JSON, which is how such providers
/// expose `assertion`).
fn cel_value(v: &Value) -> cel_interpreter::Value {
    use cel_interpreter::Value as C;
    match v {
        Value::Null => C::Null,
        Value::Bool(b) => C::Bool(*b),
        Value::Number(n) => C::Float(n.as_f64().unwrap()),
        Value::String(s) => C::String(s.clone().into()),
        Value::Array(a) => C::List(a.iter().map(cel_value).collect::<Vec<_>>().into()),
        Value::Object(o) => {
            let m: HashMap<String, C> = o.iter().map(|(k, v)| (k.clone(), cel_value(v))).collect();
            m.into()
        }
    }
}

/// Whether the provider issues a token: the condition must evaluate to
/// exactly `true`. An evaluation error (an absent claim, an unparsable
/// number) or any other value is a refusal.
fn provider_admits(payload: &Map<String, Value>) -> bool {
    let program = cel_interpreter::Program::compile(RELYING_PARTY_CONDITION).unwrap();
    let mut ctx = cel_interpreter::Context::default();
    ctx.add_variable_from_value("assertion", cel_value(&Value::Object(payload.clone())));
    matches!(
        program.execute(&ctx),
        Ok(cel_interpreter::Value::Bool(true))
    )
}

#[test]
fn the_relying_party_condition_refuses_all_but_a_fresh_attested_assertion() {
    let attested = payload(&appraised(&reference(), true, MINT), MINT);
    assert!(
        provider_admits(&attested),
        "a fresh attested assertion is admitted"
    );

    // Every tier but attested.
    for att in [
        NodeAttestation::without_evidence("no TPM"),
        NodeAttestation::of_current_evidence(&evidence(), None, MINT),
        appraised(&reference(), false, MINT),
        appraised(&contested_reference(), true, MINT),
        appraised(&reference(), true, MINT + 3600),
    ] {
        let p = payload(&att, MINT);
        assert!(!provider_admits(&p), "{} was admitted: {p:?}", att.tier());
    }

    // The age bound, at the assertion's exp: 900 s admitted, 901 s refused.
    let exp = attested["exp"].as_i64().unwrap();
    let mut at_limit = attested.clone();
    at_limit.insert(TIME_CLAIM.into(), (exp - 900).to_string().into());
    assert!(provider_admits(&at_limit));
    let mut stale = attested.clone();
    stale.insert(TIME_CLAIM.into(), (exp - 901).to_string().into());
    assert!(!provider_admits(&stale), "a stale epoch was admitted");

    // A quote time after the mint beyond the skew.
    let iat = attested["iat"].as_i64().unwrap();
    let mut future = attested.clone();
    future.insert(TIME_CLAIM.into(), (iat + 61).to_string().into());
    assert!(
        !provider_admits(&future),
        "a quote from the future was admitted"
    );

    // Each claim the condition reads, omitted.
    for claim in [TIER_CLAIM, TIME_CLAIM, "exp", "iat"] {
        let mut without = attested.clone();
        without.remove(claim);
        assert!(!provider_admits(&without), "admitted without {claim}");
    }
}

/// The provider recipe for one upstream entry (the runbook quotes it, and a
/// `nucleus-node` test, whose gate reads `docs/`, holds the two equal)
/// admits only the attested assertion for that upstream.
#[test]
fn the_recipe_for_an_upstream_admits_only_its_attested_assertions() {
    let recipe = relying_party_condition_for("model-api");
    assert!(recipe.ends_with(RELYING_PARTY_CONDITION));
    let program = cel_interpreter::Program::compile(&recipe).unwrap();
    let admits = |p: &Map<String, Value>| {
        let mut ctx = cel_interpreter::Context::default();
        ctx.add_variable_from_value("assertion", cel_value(&Value::Object(p.clone())));
        matches!(
            program.execute(&ctx),
            Ok(cel_interpreter::Value::Bool(true))
        )
    };
    let attested = payload(&appraised(&reference(), true, MINT), MINT);
    assert!(admits(&attested));
    assert!(!admits(&payload(
        &appraised(&reference(), false, MINT),
        MINT
    )));
    assert!(!admits(&payload(
        &NodeAttestation::without_evidence("x"),
        MINT
    )));
    let mut other = attested.clone();
    other.insert("nucleus_upstream".into(), "other-api".into());
    assert!(
        !admits(&other),
        "another upstream's attested assertion was admitted"
    );
}

/// The assertion's own payload carries the claims as flat strings beside the
/// existing ones, so the existing claim checks are unchanged.
#[test]
fn the_payload_stays_flat() {
    let p = payload(&appraised(&reference(), true, MINT), MINT);
    for (k, v) in &p {
        assert!(v.is_string() || v.is_u64(), "{k} is nested: {v}");
    }
    assert_eq!(p["iss"], json!(ISSUER));
}
