//! The refusals, each driven by the defect its name describes (A-19).

use base64::Engine as _;

use crate::record::BATCH_DOMAIN;
use crate::*;

const TENANT: &str = "github~example~repo";
const REPO: &str = "example/repo";
const NOW: u64 = 1_800_000_000;
const DAY: u64 = 24 * 60 * 60;

enum Signer {
    P256(p256::ecdsa::SigningKey),
    Ed25519(ed25519_dalek::SigningKey),
}

fn pem_of(der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
        out.push('\n');
    }
    out.push_str("-----END PUBLIC KEY-----\n");
    out
}

impl Signer {
    fn p256(seed: u8) -> Self {
        Self::P256(p256::ecdsa::SigningKey::from_slice(&[seed; 32]).expect("valid scalar"))
    }

    fn ed25519(seed: u8) -> Self {
        Self::Ed25519(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
    }

    fn pem(&self) -> String {
        match self {
            Self::P256(k) => {
                // SPKI of an uncompressed P-256 point: id-ecPublicKey, prime256v1, BIT STRING.
                let mut der = hex::decode("3059301306072a8648ce3d020106082a8648ce3d030107034200")
                    .expect("hex");
                der.extend_from_slice(k.verifying_key().to_encoded_point(false).as_bytes());
                pem_of(&der)
            }
            Self::Ed25519(k) => {
                let mut der = vec![
                    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
                ];
                der.extend_from_slice(k.verifying_key().as_bytes());
                pem_of(&der)
            }
        }
    }

    fn kid(&self) -> String {
        kid_for(&self.pem())
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::P256(k) => {
                use p256::ecdsa::signature::Signer as _;
                let sig: p256::ecdsa::Signature = k.sign(message);
                sig.to_der().as_bytes().to_vec()
            }
            Self::Ed25519(k) => {
                use ed25519_dalek::Signer as _;
                k.sign(message).to_bytes().to_vec()
            }
        }
    }
}

fn roots(signers: &[&Signer]) -> TrustRoots {
    let list: Vec<serde_json::Value> = signers
        .iter()
        .map(|s| serde_json::json!({"kid": s.kid(), "public_key": s.pem(), "who": "owner"}))
        .collect();
    TrustRoots::from_json(&serde_json::to_string(&list).expect("json")).expect("roots")
}

fn option(id: &str, does: &str) -> OptionBody {
    OptionBody {
        id: id.into(),
        does: does.into(),
        cost: "S".into(),
        risk: "low".into(),
    }
}

fn question(question_id: &str) -> QuestionCore {
    QuestionCore {
        tenant: TENANT.into(),
        repo: REPO.into(),
        question_id: question_id.into(),
        question: "Which way do we close the gap?".into(),
        context: vec!["one line".into(), "two lines".into()],
        evidence: vec!["docs/a.md#L1".into()],
        options: vec![
            option("a", "wire it in"),
            option("b", "narrow the claim"),
            option("c", "both"),
        ],
        recommended: Some("c".into()),
        recommended_why: "true where it runs".into(),
        proposed_scope: Scope {
            refs: vec!["example/repo#1".into()],
            paths: vec!["docs/**".into(), "README.md".into()],
            capabilities: vec!["release.publish".into()],
        },
    }
}

fn decision(q: &QuestionCore, chosen: &str) -> OwnerDecision {
    OwnerDecision {
        tenant: q.tenant.clone(),
        repo: q.repo.clone(),
        question_id: q.question_id.clone(),
        question_sha256: question_sha256(q).expect("digest"),
        options: OwnerDecision::option_digests_of(q).expect("digests"),
        chosen: chosen.into(),
        scope: q.proposed_scope.clone(),
        conditions: vec!["keep the duration".into()],
        single_use: false,
        supersedes: None,
        valid_from: NOW - 10,
        not_after: NOW + 30 * DAY,
    }
}

fn batch(signer: &Signer, decisions: Vec<OwnerDecision>) -> DecisionBatch {
    DecisionBatch {
        kid: signer.kid(),
        aud: "https://control.example/github~example~repo".into(),
        issued_at: NOW - 10,
        submit_by: NOW + 890,
        nonce: "00112233445566778899aabbccddeeff".into(),
        decisions,
    }
}

fn bundle_of(signer: &Signer, message: &[u8], index: u64, q: &QuestionCore) -> DecisionBundle {
    let b64 = base64::engine::general_purpose::STANDARD;
    DecisionBundle {
        batch_b64: b64.encode(message),
        signature: b64.encode(signer.sign(message)),
        index,
        question: q.clone(),
    }
}

fn bundle(signer: &Signer, b: &DecisionBatch, index: u64, q: &QuestionCore) -> DecisionBundle {
    bundle_of(signer, &b.message().expect("message"), index, q)
}

/// A verified standing decision for question `q-1`, signed by `signer`.
fn verified(signer: &Signer, edit: impl FnOnce(&mut OwnerDecision)) -> SignedDecision {
    let q = question("q-1");
    let mut d = decision(&q, "c");
    edit(&mut d);
    let b = batch(signer, vec![d]);
    verify(&bundle(signer, &b, 0, &q), &roots(&[signer]), NOW, TENANT).expect("verifies")
}

#[test]
fn a_decision_signed_by_a_pinned_key_verifies() {
    for signer in [Signer::p256(7), Signer::ed25519(9)] {
        let d = verified(&signer, |_| {});
        assert_eq!(d.record().chosen, "c");
        assert_eq!(d.kid(), signer.kid());
        assert_eq!(d.chosen_option().map(|o| o.does.as_str()), Some("both"));
        assert_eq!(d.id(), d.record().decision_id().expect("id"));
    }
}

/// The pending batch the control plane published on 2026-10-13: its digests were computed by
/// another implementation, so agreeing on all of them pins this encoding to that one.
#[test]
fn golden_vectors_agree_with_the_published_pending_batch() {
    let text = include_str!("../testdata/pending-2026-10-13.json");
    let file: serde_json::Value = serde_json::from_str(text).expect("json");
    let questions = file["questions"].as_array().expect("questions");
    assert_eq!(questions.len(), 17, "every published question is checked");
    for q in questions {
        let core: QuestionCore = serde_json::from_value(q["core"].clone()).expect("core");
        assert_eq!(
            question_sha256(&core).expect("digest"),
            q["question_sha256"].as_str().expect("digest field"),
            "question {}",
            core.question_id
        );
        for o in &core.options {
            assert_eq!(
                option_sha256(o).expect("digest"),
                q["option_sha256"][&o.id].as_str().expect("option digest"),
                "question {} option {}",
                core.question_id,
                o.id
            );
        }
    }
}

/// The owner's deployed approver key: its kid, as the control plane pins it, is the one
/// [`kid_for`] derives, and the key parses as P-256.
#[test]
fn the_deployed_approver_key_derives_its_pinned_kid() {
    let pem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEd3KxU/qQIom4U6VxcKSOUFd2DSBe\nlzMzQ6HOyiRAFFdH073TSAlB1V+rWtYfl1s0zbphfaYY3avCv6ZfgH4Fnw==\n-----END PUBLIC KEY-----\n";
    assert_eq!(kid_for(pem), "3f9b5f720b52f289");
    let file = serde_json::json!([{"kid": "3f9b5f720b52f289", "public_key": pem, "who": "owner"}]);
    let roots = TrustRoots::from_json(&file.to_string()).expect("parses");
    assert_eq!(roots.kids().collect::<Vec<_>>(), ["3f9b5f720b52f289"]);
}

#[test]
fn a_roots_file_whose_kid_disagrees_with_its_key_is_refused() {
    let s = Signer::p256(7);
    let file =
        serde_json::json!([{"kid": "0000000000000000", "public_key": s.pem(), "who": "owner"}]);
    assert!(matches!(
        TrustRoots::from_json(&file.to_string()),
        Err(RootsError::KidMismatch { .. })
    ));
    assert_eq!(TrustRoots::from_json("[]").err(), Some(RootsError::Empty));
    let extra =
        serde_json::json!([{"kid": s.kid(), "public_key": s.pem(), "who": "o", "alg": "x"}]);
    assert!(matches!(
        TrustRoots::from_json(&extra.to_string()),
        Err(RootsError::Malformed(_))
    ));
}

#[test]
fn a_forged_signature_is_refused() {
    let owner = Signer::p256(7);
    let forger = Signer::p256(8);
    let q = question("q-1");
    // The forger claims the owner's kid and signs with its own key.
    let b = batch(&owner, vec![decision(&q, "c")]);
    let forged = bundle(&forger, &b, 0, &q);
    assert_eq!(
        verify(&forged, &roots(&[&owner]), NOW, TENANT).err(),
        Some(DecisionError::BadSignature)
    );
    // A genuine signature with one bit flipped.
    let mut good = bundle(&owner, &b, 0, &q);
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut sig = b64.decode(&good.signature).expect("b64");
    let last = sig.len() - 1;
    sig[last] ^= 1;
    good.signature = b64.encode(sig);
    assert_eq!(
        verify(&good, &roots(&[&owner]), NOW, TENANT).err(),
        Some(DecisionError::BadSignature)
    );
}

#[test]
fn signed_bytes_edited_after_signing_are_refused() {
    let owner = Signer::ed25519(9);
    let q = question("q-1");
    let b = batch(&owner, vec![decision(&q, "c")]);
    let mut bundle = bundle(&owner, &b, 0, &q);
    let mut edited = b;
    edited.decisions[0].chosen = "a".into();
    bundle.batch_b64 =
        base64::engine::general_purpose::STANDARD.encode(edited.message().expect("message"));
    assert_eq!(
        verify(&bundle, &roots(&[&owner]), NOW, TENANT).err(),
        Some(DecisionError::BadSignature)
    );
}

#[test]
fn an_unknown_kid_is_refused() {
    let owner = Signer::p256(7);
    let stranger = Signer::ed25519(3);
    let q = question("q-1");
    let b = batch(&stranger, vec![decision(&q, "c")]);
    assert_eq!(
        verify(
            &bundle(&stranger, &b, 0, &q),
            &roots(&[&owner]),
            NOW,
            TENANT
        )
        .err(),
        Some(DecisionError::UnknownKid {
            kid: stranger.kid()
        })
    );
}

#[test]
fn a_batch_naming_another_pinned_kid_is_refused() {
    let a = Signer::p256(7);
    let b_key = Signer::ed25519(9);
    let q = question("q-1");
    let b = batch(&a, vec![decision(&q, "c")]);
    // Signed by b_key, claiming a's kid: both are pinned.
    assert!(matches!(
        verify(
            &bundle(&b_key, &b, 0, &q),
            &roots(&[&a, &b_key]),
            NOW,
            TENANT
        ),
        Err(DecisionError::SignedByOtherKid { .. })
    ));
}

#[test]
fn a_reordered_or_duplicated_key_is_noncanonical() {
    let owner = Signer::p256(7);
    let q = question("q-1");
    let b = batch(&owner, vec![decision(&q, "c")]);
    let message = b.message().expect("message");
    let body = std::str::from_utf8(&message[BATCH_DOMAIN.len()..]).expect("utf8");
    let kid = format!("\"kid\":\"{}\"", owner.kid());
    let aud = format!("\"aud\":\"{}\"", b.aud);
    assert!(body.starts_with(&format!("{{{kid},{aud},")));

    let reordered = body.replacen(&format!("{kid},{aud}"), &format!("{aud},{kid}"), 1);
    let spaced = body.replacen(',', ", ", 1);
    let duplicated = body.replacen(&kid, &format!("{kid},{kid}"), 1);
    let escaped = body.replacen("q-1", "q\\u002d1", 1);
    let missing_optional = body.replacen("\"supersedes\":null,", "", 1);
    let cases = [
        ("reordered", reordered),
        ("spaced", spaced),
        ("duplicated", duplicated),
        ("escaped", escaped),
        ("missing optional", missing_optional),
    ];
    for (name, variant) in cases {
        assert_ne!(
            variant, body,
            "{name}: the perturbation must change the bytes"
        );
        let mut m = BATCH_DOMAIN.to_vec();
        m.extend_from_slice(variant.as_bytes());
        let got = verify(
            &bundle_of(&owner, &m, 0, &q),
            &roots(&[&owner]),
            NOW,
            TENANT,
        );
        assert!(
            matches!(
                got,
                Err(DecisionError::NonCanonical | DecisionError::Malformed(_))
            ),
            "{name}: {got:?}"
        );
    }
    // Every case but the duplicate parses; those must be refused by the round-trip itself.
    let mut m = BATCH_DOMAIN.to_vec();
    m.extend_from_slice(body.replacen(',', ", ", 1).as_bytes());
    assert_eq!(decode_batch(&m).err(), Some(DecisionError::NonCanonical));
    assert_eq!(decode_batch(&message).ok(), Some(b));
}

#[test]
fn chosen_must_be_among_listed_options() {
    let owner = Signer::p256(7);
    let q = question("q-1");
    let b = batch(&owner, vec![decision(&q, "z")]);
    assert_eq!(
        verify(&bundle(&owner, &b, 0, &q), &roots(&[&owner]), NOW, TENANT).err(),
        Some(DecisionError::ChosenNotAmongOptions { chosen: "z".into() })
    );
}

#[test]
fn an_option_edit_after_proposal_changes_the_digest_and_is_refused() {
    let owner = Signer::p256(7);
    let q = question("q-1");
    let b = batch(&owner, vec![decision(&q, "c")]);
    let r = roots(&[&owner]);

    let mut edited = bundle(&owner, &b, 0, &q);
    edited.question.options[2].does = "something the owner never read".into();
    assert_eq!(
        verify(&edited, &r, NOW, TENANT).err(),
        Some(DecisionError::OptionsMismatch)
    );

    let mut reordered = bundle(&owner, &b, 0, &q);
    reordered.question.options.swap(0, 2);
    assert_eq!(
        verify(&reordered, &r, NOW, TENANT).err(),
        Some(DecisionError::OptionsMismatch)
    );

    let mut recommendation = bundle(&owner, &b, 0, &q);
    recommendation.question.recommended = Some("a".into());
    assert_eq!(
        verify(&recommendation, &r, NOW, TENANT).err(),
        Some(DecisionError::QuestionMismatch)
    );

    let mut other = bundle(&owner, &b, 0, &q);
    other.question.question_id = "q-2".into();
    assert_eq!(
        verify(&other, &r, NOW, TENANT).err(),
        Some(DecisionError::QuestionNotBound)
    );
}

#[test]
fn a_scope_wider_than_proposed_is_refused() {
    let owner = Signer::p256(7);
    let q = question("q-1");
    let mut d = decision(&q, "c");
    d.scope.paths.push("crates/**".into());
    let b = batch(&owner, vec![d]);
    assert_eq!(
        verify(&bundle(&owner, &b, 0, &q), &roots(&[&owner]), NOW, TENANT).err(),
        Some(DecisionError::ScopeWiderThanProposed {
            item: "crates/**".into()
        })
    );
}

#[test]
fn the_tenant_index_and_batch_shape_are_checked() {
    let owner = Signer::p256(7);
    let r = roots(&[&owner]);
    let q = question("q-1");
    let b = batch(&owner, vec![decision(&q, "c")]);
    assert!(matches!(
        verify(&bundle(&owner, &b, 0, &q), &r, NOW, "github~other~repo"),
        Err(DecisionError::WrongTenant { .. })
    ));
    assert!(matches!(
        verify(&bundle(&owner, &b, 1, &q), &r, NOW, TENANT),
        Err(DecisionError::IndexOutOfRange { index: 1, len: 1 })
    ));
    let q2 = question("q-0");
    let unsorted = batch(&owner, vec![decision(&q, "c"), decision(&q2, "a")]);
    assert!(matches!(
        verify(&bundle(&owner, &unsorted, 0, &q), &r, NOW, TENANT),
        Err(DecisionError::BatchShape(_))
    ));
    let mut nonce = batch(&owner, vec![decision(&q, "c")]);
    nonce.nonce = "short".into();
    assert!(matches!(
        verify(&bundle(&owner, &nonce, 0, &q), &r, NOW, TENANT),
        Err(DecisionError::BatchShape(_))
    ));
    // Two decisions in order, the second selected by index.
    let q3 = question("q-2");
    let two = batch(&owner, vec![decision(&q, "c"), decision(&q3, "b")]);
    let d = verify(&bundle(&owner, &two, 1, &q3), &r, NOW, TENANT).expect("second");
    assert_eq!(d.record().question_id, "q-2");
}

#[test]
fn a_decision_out_of_scope_is_refused_by_name() {
    let d = verified(&Signer::p256(7), |_| {});
    assert_eq!(d.covers(ScopeRef::Ref("example/repo#1")), Coverage::Covered);
    assert_eq!(
        d.covers(ScopeRef::Ref("example/repo#10")),
        Coverage::OutOfScope
    );
    assert_eq!(
        d.covers(ScopeRef::Ref("example/repo")),
        Coverage::OutOfScope
    );
    assert_eq!(d.covers(ScopeRef::Path("README.md")), Coverage::Covered);
    assert_eq!(d.covers(ScopeRef::Path("docs/a/b.md")), Coverage::Covered);
    assert_eq!(d.covers(ScopeRef::Path("docs")), Coverage::OutOfScope);
    assert_eq!(d.covers(ScopeRef::Path("docsx/a.md")), Coverage::OutOfScope);
    assert_eq!(
        d.covers(ScopeRef::Path("README.md/x")),
        Coverage::OutOfScope
    );
    assert_eq!(
        d.covers(ScopeRef::Path("crates/a.rs")),
        Coverage::OutOfScope
    );
    assert_eq!(
        d.covers(ScopeRef::Path("docs/../crates/a.rs")),
        Coverage::CannotTell
    );
    assert_eq!(d.covers(ScopeRef::Path("/docs/a.md")), Coverage::CannotTell);
    assert_eq!(
        d.covers(ScopeRef::Capability("release.publish")),
        Coverage::Covered
    );
    assert_eq!(
        d.covers(ScopeRef::Capability("release")),
        Coverage::OutOfScope
    );

    let writes = vec!["docs/a.md".to_string(), "crates/x.rs".to_string()];
    let act = |w| Action {
        capability: "release.publish",
        writes: w,
    };
    assert_eq!(
        d.covers_action(&act(WriteSet::Known(&writes[..1]))),
        Coverage::Covered
    );
    assert_eq!(
        d.covers_action(&act(WriteSet::Known(&writes))),
        Coverage::OutOfScope
    );
    assert_eq!(
        d.covers_action(&act(WriteSet::Unknown)),
        Coverage::CannotTell
    );

    let mut ledger = DecisionLedger::empty();
    let id = ledger.hold(d).expect("held");
    assert_eq!(
        ledger.cite(id, &act(WriteSet::Known(&writes)), NOW).err(),
        Some(LedgerError::OutOfScope(id))
    );
    assert_eq!(
        ledger.cite(id, &act(WriteSet::Unknown), NOW).err(),
        Some(LedgerError::CannotTell(id))
    );
    assert!(
        ledger
            .cite(id, &act(WriteSet::Known(&writes[..1])), NOW)
            .is_ok()
    );
}

#[test]
fn a_pattern_outside_the_grammar_never_covers() {
    let owner = Signer::p256(7);
    let mut q = question("q-1");
    q.proposed_scope.paths = vec!["src/*.rs".into()];
    let b = batch(&owner, vec![decision(&q, "c")]);
    let d = verify(&bundle(&owner, &b, 0, &q), &roots(&[&owner]), NOW, TENANT).expect("ok");
    assert_eq!(d.covers(ScopeRef::Path("src/a.rs")), Coverage::CannotTell);
}

#[test]
fn expired_and_superseded_decisions_refuse() {
    let owner = Signer::p256(7);
    let r = roots(&[&owner]);
    let q = question("q-1");
    let b = batch(&owner, vec![decision(&q, "c")]);
    let first = bundle(&owner, &b, 0, &q);

    let d = decision(&q, "c");
    assert_eq!(
        verify(&first, &r, d.not_after + 1, TENANT).err(),
        Some(DecisionError::Expired {
            not_after: d.not_after,
            now: d.not_after + 1
        })
    );
    assert!(matches!(
        verify(&first, &r, d.valid_from - 1, TENANT),
        Err(DecisionError::NotYetValid { .. })
    ));
    let mut long = decision(&q, "c");
    long.not_after = long.valid_from + 366 * DAY;
    assert_eq!(
        verify(
            &bundle(&owner, &batch(&owner, vec![long]), 0, &q),
            &r,
            NOW,
            TENANT
        )
        .err(),
        Some(DecisionError::BadWindow)
    );

    // Expiry is re-checked on use, not only at verification.
    let none: [String; 0] = [];
    let act = Action {
        capability: "release.publish",
        writes: WriteSet::Known(&none),
    };
    let mut ledger = DecisionLedger::empty();
    let old = ledger
        .hold(verify(&first, &r, NOW, TENANT).expect("ok"))
        .expect("held");
    assert_eq!(
        ledger.cite(old, &act, d.not_after + 1).err(),
        Some(LedgerError::Expired(old))
    );

    // The owner decides again, naming the first decision as superseded.
    let mut again = decision(&q, "b");
    again.supersedes = Some(old.to_hex());
    let mut b2 = batch(&owner, vec![again]);
    b2.nonce = "ffeeddccbbaa99887766554433221100".into();
    let new = ledger
        .hold(verify(&bundle(&owner, &b2, 0, &q), &r, NOW, TENANT).expect("ok"))
        .expect("held");
    assert_eq!(
        ledger.cite(old, &act, NOW).err(),
        Some(LedgerError::Superseded { id: old, by: new })
    );
    assert_eq!(
        ledger
            .hold(verify(&first, &r, NOW, TENANT).expect("still verifies"))
            .err(),
        Some(LedgerError::Superseded { id: old, by: new })
    );
    assert_eq!(ledger.len(), 1);
    assert!(ledger.cite(new, &act, NOW).is_ok());
}

#[test]
fn a_one_shot_decision_cannot_be_spent_twice() {
    let owner = Signer::ed25519(9);
    let r = roots(&[&owner]);
    let q = question("q-1");
    let mut d = decision(&q, "c");
    d.single_use = true;
    let b = batch(&owner, vec![d]);
    let bundle = bundle(&owner, &b, 0, &q);
    let none: [String; 0] = [];
    let act = Action {
        capability: "release.publish",
        writes: WriteSet::Known(&none),
    };

    let mut ledger = DecisionLedger::empty();
    let id = ledger
        .hold(verify(&bundle, &r, NOW, TENANT).expect("ok"))
        .expect("held");
    assert_eq!(
        ledger.cite(id, &act, NOW).err(),
        Some(LedgerError::OneShot(id))
    );
    // A refused spend leaves it held.
    let wrong = Action {
        capability: "other",
        writes: WriteSet::Known(&none),
    };
    assert_eq!(
        ledger.spend(id, &wrong, NOW).err(),
        Some(LedgerError::OutOfScope(id))
    );
    let spent = ledger.spend(id, &act, NOW).expect("first spend");
    assert_eq!(spent.decision(), id);
    assert_eq!(spent.capability(), "release.publish");
    assert_eq!(
        ledger.spend(id, &act, NOW).err(),
        Some(LedgerError::Spent(id))
    );

    // The same bytes verified again yield a decision with the same id, which is refused.
    let copy = verify(&bundle, &r, NOW, TENANT).expect("still verifies");
    assert_eq!(
        ledger.consume(copy, &act, NOW).err(),
        Some(LedgerError::Spent(id))
    );
    let copy = verify(&bundle, &r, NOW, TENANT).expect("still verifies");
    assert_eq!(ledger.hold(copy).err(), Some(LedgerError::Spent(id)));

    // A standing decision is not spendable.
    let standing = verified(&owner, |_| {});
    let sid = ledger.hold(standing).expect("held");
    assert_eq!(
        ledger.spend(sid, &act, NOW).err(),
        Some(LedgerError::Standing(sid))
    );
}

#[test]
fn a_bundle_with_an_unknown_field_is_refused() {
    let owner = Signer::p256(7);
    let q = question("q-1");
    let b = batch(&owner, vec![decision(&q, "c")]);
    let mut v = serde_json::to_value(bundle(&owner, &b, 0, &q)).expect("json");
    v["authority"] = serde_json::json!("owner approved");
    assert!(matches!(
        DecisionBundle::from_slice(v.to_string().as_bytes()),
        Err(DecisionError::BadBundle(_))
    ));
}

#[test]
fn decision_ids_parse_only_as_lowercase_hex() {
    let id = verified(&Signer::p256(7), |_| {}).id();
    assert_eq!(DecisionId::from_hex(&id.to_hex()), Ok(id));
    assert_eq!(
        DecisionId::from_hex(&id.to_hex().to_uppercase()),
        Err(DecisionError::BadId)
    );
    assert_eq!(
        DecisionId::from_hex("../etc/passwd"),
        Err(DecisionError::BadId)
    );
}
