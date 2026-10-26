//! The refusals, each driven by the defect its name describes (A-19), over real signed
//! execution receipts, real judge signatures and a real owner waiver.

use std::collections::BTreeMap;

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use nucleus_ci_verdict::execution::{
    ArtifactIdentity, Backend, ExecutionClaim, ExecutionSchema, NodePlatform, RecordedExecution,
    SandboxTier,
};
use nucleus_receipt::{Projection, Receipt, Session};
use nucleus_signed_decision::{
    DecisionBatch, DecisionBundle, OptionBody, OwnerDecision, QuestionCore, Scope, TrustRoots,
    kid_for, question_sha256,
};
use sha2::{Digest, Sha256};

use crate::improve::{Movement, movement};
use crate::*;

const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PLAN: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const R0: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const R1: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const R2: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const J1: &str = "4444444444444444444444444444444444444444444444444444444444444444";
const NOW: u64 = 1_800_000_000;
const TENANT: &str = "github~example~judge";
const GATES: [&str; 3] = ["fmt", "ledger", "test"];

fn executor() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}
fn judge0() -> SigningKey {
    SigningKey::from_bytes(&[11; 32])
}
fn judge1() -> SigningKey {
    SigningKey::from_bytes(&[12; 32])
}
fn owner() -> SigningKey {
    SigningKey::from_bytes(&[21; 32])
}
fn hex_key(k: &SigningKey) -> String {
    hex::encode(k.verifying_key().to_bytes())
}

// ── Seed ────────────────────────────────────────────────────────────────────

fn seed_with(min_tier: Tier) -> Seed {
    Seed {
        chain: "example runtime + judge".into(),
        runtime_repo: "example/runtime".into(),
        judge_repo: "example/judge".into(),
        owner_tenant: TENANT.into(),
        judge_kid: "judge-0".into(),
        judge_key: hex_key(&judge0()),
        runtime_release_sha256: R0.into(),
        judge_release_sha256: J1.into(),
        directions: BTreeMap::from([
            ("runtime.passing_tests".into(), Direction::Higher),
            ("runtime.open_findings".into(), Direction::Lower),
            ("runtime.corpus_steps".into(), Direction::Guard),
            ("judge.gates_on_runtime".into(), Direction::Higher),
        ]),
        ledger: BTreeMap::from([
            ("runtime.passing_tests".into(), 100),
            ("runtime.open_findings".into(), 9),
            ("runtime.corpus_steps".into(), 430),
            ("judge.gates_on_runtime".into(), 1),
        ]),
        min_tier,
        issued_at: NOW - 100,
    }
}

fn seed_bytes(seed: &Seed) -> (Vec<u8>, String) {
    let bytes = encode(seed).unwrap();
    let id = id_of(SEED_DOMAIN, &bytes);
    (bytes, id)
}

// ── Evidence ────────────────────────────────────────────────────────────────

fn claim(gate: &str, commit: &str, tree: &str, exit: Option<i32>) -> ExecutionClaim {
    ExecutionClaim {
        schema: ExecutionSchema::V1,
        pod_id: format!("pod-{gate}"),
        source_commit: commit.into(),
        source_tree: tree.into(),
        gate: gate.into(),
        program_digest: DIGEST.into(),
        architecture: "x86_64".into(),
        backend: Backend::Firecracker,
        uid_isolated: true,
        exit_code: exit,
        stdout_sha256: DIGEST.into(),
        stderr_sha256: DIGEST.into(),
        launch_hash: DIGEST.into(),
        environment_inputs_sha256: DIGEST.into(),
        environment_complete_sha256: DIGEST.into(),
        artifacts: BTreeMap::new(),
        node_platform: NodePlatform::Evidence {
            evidence_sha256: DIGEST.into(),
            epoch: 4,
        },
        sandbox_tier: SandboxTier::Driver,
    }
}

fn expectation(c: &ExecutionClaim, key: &SigningKey) -> RecordedExecution {
    RecordedExecution {
        pod_id: c.pod_id.clone(),
        source_commit: c.source_commit.clone(),
        source_tree: c.source_tree.clone(),
        gate: c.gate.clone(),
        program_digest: DIGEST.into(),
        architecture: "x86_64".into(),
        environment_inputs_sha256: DIGEST.into(),
        artifacts: c
            .artifacts
            .iter()
            .map(|(k, a)| (k.clone(), a.path.clone()))
            .collect(),
        session_id: c.pod_id.clone(),
        issuer_kid: "executor-1".into(),
        verifying_key: key.verifying_key().to_bytes(),
        issued_not_before_micros: 100,
        issued_not_after_micros: 200,
    }
}

fn receipt_b64(c: &ExecutionClaim, key: &SigningKey) -> String {
    let receipt = Receipt::sign(
        Session {
            session_id: c.pod_id.clone(),
            issuer_kid: "executor-1".into(),
            issued_at_micros: 150,
            parent_chain: vec![],
        },
        vec![Projection::Ci(serde_json::to_value(c).unwrap())],
        key,
    );
    base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&receipt).unwrap())
}

fn evidence_for(c: ExecutionClaim) -> GateEvidence {
    let key = executor();
    GateEvidence {
        receipt_b64: receipt_b64(&c, &key),
        expected: expectation(&c, &key),
    }
}

/// Every required gate passing on `commit`/`tree`, the ledger gate emitting exactly `ledger`.
fn evidence(commit: &str, tree: &str, ledger: &BTreeMap<String, i64>) -> Vec<GateEvidence> {
    let bytes = ledger_bytes(ledger).unwrap();
    GATES
        .iter()
        .map(|g| {
            let mut c = claim(g, commit, tree, Some(0));
            if *g == "ledger" {
                c.artifacts.insert(
                    "ledger".into(),
                    ArtifactIdentity {
                        path: "ledger.json".into(),
                        sha256: hex::encode(Sha256::digest(&bytes)),
                        size: bytes.len() as u64,
                    },
                );
            }
            evidence_for(c)
        })
        .collect()
}

// ── Generations ─────────────────────────────────────────────────────────────

fn runtime_ledger(passing: i64, findings: i64, corpus: i64) -> BTreeMap<String, i64> {
    BTreeMap::from([
        ("runtime.passing_tests".into(), passing),
        ("runtime.open_findings".into(), findings),
        ("runtime.corpus_steps".into(), corpus),
    ])
}

fn generation(
    seed_id: &str,
    number: u64,
    parent: &str,
    role: Role,
    ledger: BTreeMap<String, i64>,
    judged_by: &str,
    judge_kid: &str,
) -> Generation {
    let (repo, release, next_judge) = match role {
        Role::Runtime => ("example/runtime", R1, None),
        Role::Judge => (
            "example/judge",
            R2,
            Some(JudgeKey {
                kid: "judge-1".into(),
                key: hex_key(&judge1()),
            }),
        ),
    };
    let commit = format!("commit-{number}");
    let tree = format!("tree-{number}");
    Generation {
        seed: seed_id.into(),
        number,
        parent: parent.into(),
        role,
        repo: repo.into(),
        evidence: evidence(&commit, &tree, &ledger),
        source_commit: commit,
        source_tree: tree,
        plan_sha256: PLAN.into(),
        required_gates: GATES.iter().map(|g| g.to_string()).collect(),
        ledger_gate: "ledger".into(),
        ledger_artifact: "ledger".into(),
        ledger,
        added_directions: BTreeMap::new(),
        waiver: None,
        builds: vec![Build {
            builder: "lane-x86-1".into(),
            architecture: "x86_64".into(),
            artifact_sha256: release.into(),
        }],
        release_sha256: release.into(),
        next_judge,
        judged_by: judged_by.into(),
        judge_kid: judge_kid.into(),
        issued_at: NOW + number,
    }
}

fn sign_bytes(body: &[u8], key: &SigningKey) -> SignedGeneration {
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut message = GENERATION_DOMAIN.to_vec();
    message.extend_from_slice(body);
    SignedGeneration {
        body_b64: b64.encode(body),
        signature_b64: b64.encode(key.sign(&message).to_bytes()),
    }
}

fn sign(g: &Generation, key: &SigningKey) -> (SignedGeneration, String) {
    let body = encode(g).unwrap();
    (sign_bytes(&body, key), id_of(GENERATION_DOMAIN, &body))
}

// ── Owner waiver ────────────────────────────────────────────────────────────

fn owner_pem() -> String {
    let mut der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    der.extend_from_slice(owner().verifying_key().as_bytes());
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    format!("-----BEGIN PUBLIC KEY-----\n{b64}\n-----END PUBLIC KEY-----\n")
}

fn owner_roots() -> TrustRoots {
    let pem = owner_pem();
    let list = serde_json::json!([{"kid": kid_for(&pem), "public_key": pem, "who": "owner"}]);
    TrustRoots::from_json(&list.to_string()).unwrap()
}

fn waiver(capabilities: Vec<String>) -> DecisionBundle {
    let option = |id: &str| OptionBody {
        id: id.into(),
        does: format!("option {id}"),
        cost: "S".into(),
        risk: "low".into(),
    };
    let question = QuestionCore {
        tenant: TENANT.into(),
        repo: "example/runtime".into(),
        question_id: "regress-open-findings".into(),
        question: "May this generation let a metric regress?".into(),
        context: vec!["a repair that cannot hold every number".into()],
        evidence: vec![],
        options: vec![option("a"), option("b")],
        recommended: Some("a".into()),
        recommended_why: "named and dated".into(),
        proposed_scope: Scope {
            refs: vec![],
            paths: vec![],
            capabilities: capabilities.clone(),
        },
    };
    let decision = OwnerDecision {
        tenant: TENANT.into(),
        repo: "example/runtime".into(),
        question_id: question.question_id.clone(),
        question_sha256: question_sha256(&question).unwrap(),
        options: OwnerDecision::option_digests_of(&question).unwrap(),
        chosen: "a".into(),
        scope: question.proposed_scope.clone(),
        conditions: vec![],
        single_use: true,
        supersedes: None,
        valid_from: NOW - 10,
        not_after: NOW + 86_400,
    };
    let batch = DecisionBatch {
        kid: kid_for(&owner_pem()),
        aud: "https://control.example/github~example~judge".into(),
        issued_at: NOW - 10,
        submit_by: NOW + 890,
        nonce: "00112233445566778899aabbccddeeff".into(),
        decisions: vec![decision],
    };
    let message = batch.message().unwrap();
    let b64 = base64::engine::general_purpose::STANDARD;
    DecisionBundle {
        batch_b64: b64.encode(&message),
        signature: b64.encode(owner().sign(&message).to_bytes()),
        index: 0,
        question,
    }
}

// ── Harness ─────────────────────────────────────────────────────────────────

fn check(seed: &Seed, chain: &[SignedGeneration]) -> Result<VerifiedChain, ChainError> {
    let (bytes, id) = seed_bytes(seed);
    let roots = owner_roots();
    let keys = [executor().verifying_key().to_bytes()];
    verify_chain(
        &bytes,
        chain,
        &Pins {
            seed_id: &id,
            executor_keys: &keys,
            owner_roots: &roots,
        },
    )
}

/// One runtime generation on the seed, after `edit`, and the refusal (if any) at position 1.
fn first(edit: impl FnOnce(&mut Generation)) -> Result<VerifiedChain, ChainError> {
    let seed = seed_with(Tier::Disagreed);
    let (_, seed_id) = seed_bytes(&seed);
    let mut g = generation(
        &seed_id,
        1,
        &seed_id,
        Role::Runtime,
        runtime_ledger(101, 9, 430),
        &seed_id,
        "judge-0",
    );
    edit(&mut g);
    check(&seed, &[sign(&g, &judge0()).0])
}

fn refusal(r: Result<VerifiedChain, ChainError>) -> Refusal {
    match r {
        Err(ChainError::Generation { refusal, .. }) => refusal,
        other => panic!("expected a generation refusal, got {other:?}"),
    }
}

/// Rebuild the ledger gate's evidence so its artifact names `ledger` (an honest gate whose
/// numbers simply moved the wrong way).
fn honest(g: &mut Generation, ledger: BTreeMap<String, i64>) {
    g.evidence = evidence(&g.source_commit, &g.source_tree, &ledger);
    g.ledger = ledger;
}

// ── The happy chain ─────────────────────────────────────────────────────────

/// Runtime 1 judged by the seed's judge; judge 2 judged by the seed's judge and naming a
/// successor key; runtime 3 judged by judge 2 under that key. Releases and the ledger follow.
#[test]
fn a_three_generation_chain_verifies_and_the_judge_hands_over() {
    let seed = seed_with(Tier::Disagreed);
    let (_, seed_id) = seed_bytes(&seed);

    let g1 = generation(
        &seed_id,
        1,
        &seed_id,
        Role::Runtime,
        runtime_ledger(101, 9, 430),
        &seed_id,
        "judge-0",
    );
    let (s1, id1) = sign(&g1, &judge0());

    let g2 = generation(
        &seed_id,
        2,
        &id1,
        Role::Judge,
        BTreeMap::from([("judge.gates_on_runtime".into(), 2)]),
        &seed_id,
        "judge-0",
    );
    let (s2, id2) = sign(&g2, &judge0());

    let g3 = generation(
        &seed_id,
        3,
        &id2,
        Role::Runtime,
        runtime_ledger(101, 8, 430),
        &id2,
        "judge-1",
    );
    let (s3, id3) = sign(&g3, &judge1());

    let chain = check(&seed, &[s1, s2, s3]).expect("verifies");
    assert_eq!(
        chain.generation(),
        id3,
        "decided against the head it verified"
    );
    let gens = chain.generations();
    assert_eq!(gens.len(), 3);
    assert_eq!(gens[0].improved(), ["runtime.passing_tests"]);
    assert_eq!(gens[1].role(), Role::Judge);
    assert_eq!(gens[2].improved(), ["runtime.open_findings"]);
    assert!(gens.iter().all(|g| g.tier() == Tier::SingleBuilder));
    assert_eq!(chain.runtime_release(), R1);
    assert_eq!(chain.judge_release(), R2);
    assert_eq!(chain.ledger()["runtime.open_findings"], 8);
    assert_eq!(chain.ledger()["judge.gates_on_runtime"], 2);
}

// ── A candidate never judges itself ─────────────────────────────────────────

/// A judge candidate that signs its own certificate with the key it is asking to be trusted
/// with is refused: only the current judge's key verifies.
#[test]
fn a_judge_candidate_cannot_sign_its_own_admission() {
    let seed = seed_with(Tier::Disagreed);
    let (_, seed_id) = seed_bytes(&seed);
    let g1 = generation(
        &seed_id,
        1,
        &seed_id,
        Role::Judge,
        BTreeMap::from([("judge.gates_on_runtime".into(), 2)]),
        &seed_id,
        "judge-0",
    );
    let (self_signed, _) = sign(&g1, &judge1());
    assert_eq!(refusal(check(&seed, &[self_signed])), Refusal::BadSignature);
}

/// Once a successor judge is promoted, the retired judge can no longer admit anything.
#[test]
fn a_retired_judge_cannot_admit_after_its_successor_is_promoted() {
    let seed = seed_with(Tier::Disagreed);
    let (_, seed_id) = seed_bytes(&seed);
    let g1 = generation(
        &seed_id,
        1,
        &seed_id,
        Role::Judge,
        BTreeMap::from([("judge.gates_on_runtime".into(), 2)]),
        &seed_id,
        "judge-0",
    );
    let (s1, id1) = sign(&g1, &judge0());
    let g2 = generation(
        &seed_id,
        2,
        &id1,
        Role::Runtime,
        runtime_ledger(101, 9, 430),
        &seed_id,
        "judge-0",
    );
    let (stale, _) = sign(&g2, &judge0());
    assert_eq!(refusal(check(&seed, &[s1, stale])), Refusal::BadSignature);
}

/// Signed by the right key but naming a judge generation that is not the current one.
#[test]
fn naming_a_judge_other_than_the_current_one_is_refused() {
    let r = first(|g| g.judged_by = R0.into());
    assert!(matches!(refusal(r), Refusal::NotCurrentJudge { .. }));
    let r = first(|g| g.judge_kid = "judge-9".into());
    assert!(matches!(refusal(r), Refusal::JudgeKid { .. }));
}

// ── Each generation must improve ────────────────────────────────────────────

#[test]
fn holding_every_number_steady_is_refused() {
    let r = first(|g| honest(g, runtime_ledger(100, 9, 430)));
    assert_eq!(refusal(r), Refusal::NoImprovement);
}

#[test]
fn a_guard_rising_is_not_an_improvement() {
    let r = first(|g| honest(g, runtime_ledger(100, 9, 999)));
    assert_eq!(refusal(r), Refusal::NoImprovement);
}

/// Adding a metric that "improves" by existing does not satisfy the rule.
#[test]
fn a_new_metric_cannot_be_the_improvement() {
    let r = first(|g| {
        let mut l = runtime_ledger(100, 9, 430);
        l.insert("runtime.shiny".into(), 1);
        honest(g, l);
        g.added_directions
            .insert("runtime.shiny".into(), Direction::Higher);
    });
    assert_eq!(refusal(r), Refusal::NoImprovement);
}

#[test]
fn a_regression_without_a_waiver_is_refused() {
    let r = first(|g| honest(g, runtime_ledger(101, 10, 430)));
    assert_eq!(
        refusal(r),
        Refusal::Unwaived("runtime.open_findings".into())
    );
    let r = first(|g| honest(g, runtime_ledger(101, 9, 429)));
    assert_eq!(refusal(r), Refusal::Unwaived("runtime.corpus_steps".into()));
}

#[test]
fn the_owner_can_waive_a_named_regression_and_it_is_shown() {
    let seed = seed_with(Tier::Disagreed);
    let (_, seed_id) = seed_bytes(&seed);
    let cap = waiver_capability(&seed_id, 1, "runtime.open_findings");
    let r = first(|g| {
        honest(g, runtime_ledger(101, 10, 430));
        g.waiver = Some(waiver(vec![cap]));
    });
    let chain = r.expect("waived");
    assert_eq!(chain.generations()[0].waived(), ["runtime.open_findings"]);
}

/// A waiver for another generation, or another metric, waives nothing here.
#[test]
fn a_waiver_for_another_generation_or_metric_does_not_cover() {
    let seed = seed_with(Tier::Disagreed);
    let (_, seed_id) = seed_bytes(&seed);
    for cap in [
        waiver_capability(&seed_id, 2, "runtime.open_findings"),
        waiver_capability(&seed_id, 1, "runtime.passing_tests"),
        waiver_capability(R0, 1, "runtime.open_findings"),
    ] {
        let r = first(|g| {
            honest(g, runtime_ledger(101, 10, 430));
            g.waiver = Some(waiver(vec![cap]));
        });
        assert_eq!(
            refusal(r),
            Refusal::Unwaived("runtime.open_findings".into())
        );
    }
}

/// No waiver can excuse a generation that improved nothing.
#[test]
fn a_waiver_cannot_excuse_no_improvement() {
    let seed = seed_with(Tier::Disagreed);
    let (_, seed_id) = seed_bytes(&seed);
    let cap = waiver_capability(&seed_id, 1, "runtime.open_findings");
    let r = first(|g| {
        honest(g, runtime_ledger(100, 10, 430));
        g.waiver = Some(waiver(vec![cap]));
    });
    assert_eq!(refusal(r), Refusal::NoImprovement);
}

#[test]
fn a_forged_waiver_is_refused() {
    let seed = seed_with(Tier::Disagreed);
    let (_, seed_id) = seed_bytes(&seed);
    let cap = waiver_capability(&seed_id, 1, "runtime.open_findings");
    let r = first(|g| {
        honest(g, runtime_ledger(101, 10, 430));
        let mut w = waiver(vec![cap]);
        w.signature = base64::engine::general_purpose::STANDARD
            .encode(judge0().sign(b"not the owner").to_bytes());
        g.waiver = Some(w);
    });
    assert!(matches!(refusal(r), Refusal::Waiver(_)));
}

#[test]
fn an_unused_waiver_is_refused() {
    let seed = seed_with(Tier::Disagreed);
    let (_, seed_id) = seed_bytes(&seed);
    let cap = waiver_capability(&seed_id, 1, "runtime.open_findings");
    let r = first(|g| g.waiver = Some(waiver(vec![cap])));
    assert_eq!(refusal(r), Refusal::UnusedWaiver);
}

// ── The numbers are measured ────────────────────────────────────────────────

/// The certificate claims numbers its ledger gate did not produce.
#[test]
fn a_ledger_the_gate_did_not_produce_is_refused() {
    let r = first(|g| {
        g.ledger = runtime_ledger(500, 0, 430);
    });
    assert_eq!(refusal(r), Refusal::LedgerBinding);
}

#[test]
fn a_ledger_artifact_from_no_required_gate_is_refused() {
    let r = first(|g| g.ledger_artifact = "other".into());
    assert!(matches!(refusal(r), Refusal::LedgerSource(_)));
    let r = first(|g| g.ledger_gate = "lint".into());
    assert!(matches!(refusal(r), Refusal::LedgerSource(_)));
}

#[test]
fn a_vanished_metric_is_refused() {
    let r = first(|g| {
        let mut l = runtime_ledger(101, 9, 430);
        l.remove("runtime.corpus_steps");
        honest(g, l);
    });
    assert_eq!(refusal(r), Refusal::Vanished("runtime.corpus_steps".into()));
}

#[test]
fn a_direction_cannot_be_changed() {
    let r = first(|g| {
        g.added_directions
            .insert("runtime.open_findings".into(), Direction::Higher);
    });
    assert_eq!(
        refusal(r),
        Refusal::Redirected("runtime.open_findings".into())
    );
}

#[test]
fn a_metric_with_no_direction_is_refused() {
    let r = first(|g| {
        let mut l = runtime_ledger(101, 9, 430);
        l.insert("runtime.untyped".into(), 1);
        honest(g, l);
    });
    assert_eq!(refusal(r), Refusal::NoDirection("runtime.untyped".into()));
}

/// A runtime generation may not move the judge's numbers.
#[test]
fn a_generation_may_move_only_its_own_namespace() {
    let r = first(|g| {
        let mut l = runtime_ledger(101, 9, 430);
        l.insert("judge.gates_on_runtime".into(), 50);
        honest(g, l);
    });
    assert_eq!(
        refusal(r),
        Refusal::Namespace("judge.gates_on_runtime".into())
    );
}

// ── Every required gate ran on this tree and passed ─────────────────────────

#[test]
fn a_failing_or_missing_result_is_not_a_pass() {
    for exit in [Some(1), None] {
        let r = first(|g| {
            g.evidence[0] = evidence_for(claim("fmt", &g.source_commit, &g.source_tree, exit));
        });
        assert_eq!(
            refusal(r),
            Refusal::GateFailed {
                gate: "fmt".into(),
                exit
            }
        );
    }
}

#[test]
fn a_missing_gate_is_missing_evidence() {
    let r = first(|g| {
        g.evidence.remove(2);
    });
    assert_eq!(refusal(r), Refusal::EvidenceShape("test".into()));
}

#[test]
fn unsorted_or_repeated_required_gates_are_refused() {
    let r = first(|g| g.required_gates.swap(0, 2));
    assert_eq!(refusal(r), Refusal::RequiredGates);
    let r = first(|g| g.required_gates.clear());
    assert_eq!(refusal(r), Refusal::RequiredGates);
}

/// Evidence from another tree, whether the expectation admits it or not.
#[test]
fn evidence_for_another_tree_is_refused() {
    let r = first(|g| {
        g.evidence[2] = evidence_for(claim("test", &g.source_commit, "tree-other", Some(0)));
    });
    assert_eq!(refusal(r), Refusal::WrongSubject("test".into()));
    let r = first(|g| {
        let key = executor();
        let honest_claim = claim("test", &g.source_commit, &g.source_tree, Some(0));
        let other = claim("test", &g.source_commit, "tree-other", Some(0));
        g.evidence[2] = GateEvidence {
            receipt_b64: receipt_b64(&other, &key),
            expected: expectation(&honest_claim, &key),
        };
    });
    assert!(matches!(refusal(r), Refusal::Execution { .. }));
}

/// A receipt that verifies perfectly under a key nobody pinned counts for nothing.
#[test]
fn an_unpinned_executor_is_refused() {
    let r = first(|g| {
        let rogue = SigningKey::from_bytes(&[99; 32]);
        let c = claim("test", &g.source_commit, &g.source_tree, Some(0));
        g.evidence[2] = GateEvidence {
            receipt_b64: receipt_b64(&c, &rogue),
            expected: expectation(&c, &rogue),
        };
    });
    assert_eq!(refusal(r), Refusal::UnpinnedExecutor("test".into()));
}

// ── Where it sits in the chain ──────────────────────────────────────────────

#[test]
fn sequence_parent_seed_and_repository_are_checked() {
    assert!(matches!(
        refusal(first(|g| g.number = 2)),
        Refusal::Number { .. }
    ));
    assert!(matches!(
        refusal(first(|g| g.parent = R0.into())),
        Refusal::Parent(_)
    ));
    assert!(matches!(
        refusal(first(|g| g.seed = R0.into())),
        Refusal::WrongSeed(_)
    ));
    assert!(matches!(
        refusal(first(|g| g.repo = "example/judge".into())),
        Refusal::Repo(_)
    ));
    assert!(matches!(
        refusal(first(|g| g.issued_at = NOW - 1_000)),
        Refusal::IssuedBackwards { .. }
    ));
}

#[test]
fn a_seed_other_than_the_pinned_one_is_refused() {
    let seed = seed_with(Tier::Disagreed);
    let (bytes, _) = seed_bytes(&seed);
    let roots = owner_roots();
    let keys = [executor().verifying_key().to_bytes()];
    let r = verify_chain(
        &bytes,
        &[],
        &Pins {
            seed_id: R0,
            executor_keys: &keys,
            owner_roots: &roots,
        },
    );
    assert!(matches!(
        r,
        Err(ChainError::Seed(SeedError::NotPinned { .. }))
    ));
}

/// The judge signed these exact bytes, but they are not the one encoding, so two byte
/// strings would name one generation.
#[test]
fn a_non_canonical_body_is_refused_even_when_signed() {
    let seed = seed_with(Tier::Disagreed);
    let (_, seed_id) = seed_bytes(&seed);
    let g = generation(
        &seed_id,
        1,
        &seed_id,
        Role::Runtime,
        runtime_ledger(101, 9, 430),
        &seed_id,
        "judge-0",
    );
    let mut body = encode(&g).unwrap();
    body.push(b' ');
    let r = check(&seed, &[sign_bytes(&body, &judge0())]);
    assert_eq!(refusal(r), Refusal::Decode(DecodeError::NotCanonical));
}

// ── Reproduction tier and successor keys ────────────────────────────────────

#[test]
fn the_reproduction_tier_is_computed_and_shown() {
    let two = |second: &'static str| {
        move |g: &mut Generation| {
            g.builds.push(Build {
                builder: "mac-arm64".into(),
                architecture: "aarch64".into(),
                artifact_sha256: second.into(),
            });
        }
    };
    let chain = first(two(R1)).unwrap();
    assert_eq!(chain.generations()[0].tier(), Tier::Reproduced);
    let chain = first(two(R2)).unwrap();
    assert_eq!(chain.generations()[0].tier(), Tier::Disagreed);
    assert_eq!(
        refusal(first(|g| g.release_sha256 = R2.into())),
        Refusal::ReleaseNotBuilt
    );
    assert_eq!(refusal(first(|g| g.builds.clear())), Refusal::Builds);
}

#[test]
fn a_tier_below_the_seeds_floor_is_refused() {
    let seed = seed_with(Tier::Reproduced);
    let (_, seed_id) = seed_bytes(&seed);
    let g = generation(
        &seed_id,
        1,
        &seed_id,
        Role::Runtime,
        runtime_ledger(101, 9, 430),
        &seed_id,
        "judge-0",
    );
    let r = check(&seed, &[sign(&g, &judge0()).0]);
    assert!(matches!(refusal(r), Refusal::BelowTier { .. }));
}

#[test]
fn a_successor_key_exactly_when_the_role_is_the_judge() {
    let r = first(|g| {
        g.next_judge = Some(JudgeKey {
            kid: "judge-1".into(),
            key: hex_key(&judge1()),
        })
    });
    assert_eq!(refusal(r), Refusal::NextJudge);
}

// ── The order itself ────────────────────────────────────────────────────────

#[test]
fn movement_follows_direction() {
    use Direction::*;
    for (d, before, after, want) in [
        (Higher, 1, 2, Movement::Improved),
        (Higher, 2, 1, Movement::Regressed),
        (Lower, 2, 1, Movement::Improved),
        (Lower, 1, 2, Movement::Regressed),
        (Guard, 1, 2, Movement::Held),
        (Guard, 2, 1, Movement::Regressed),
        (Higher, 1, 1, Movement::Held),
        (Lower, 1, 1, Movement::Held),
        (Guard, 1, 1, Movement::Held),
    ] {
        assert_eq!(
            movement(d, before, after),
            want,
            "{d:?} {before} -> {after}"
        );
    }
}
