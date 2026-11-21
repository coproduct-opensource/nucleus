//! The whole workflow, through the HTTP surface, with a toy model.
//!
//! Five parties, each using only its own key and public material: a deployer,
//! an editor, a runner, an evaluator and the registry. The checkpoint is three
//! small tensors and the "model" is a function of them, so that which
//! checkpoint answered is visible in the answer as well as in the digest the
//! endpoint reports.
//!
//! What is shown, in order:
//!
//! 1. the endpoint serves the genesis checkpoint;
//! 2. serving stays on it when a higher-scoring candidate has no approval,
//!    when the evaluation receipt belongs to another checkpoint, and when the
//!    patch touches a tensor it may not;
//! 3. a candidate with a complete chain is promoted and the endpoint serves
//!    it, with the previous digest retained;
//! 4. a verifier holding only files replays the patch to the same digest and
//!    recomputes the scores;
//! 5. a second round runs from the promoted checkpoint, under a fresh grant
//!    that cites the first release, and the first round's grant is refused;
//! 6. rollback returns the endpoint to the previous checkpoint;
//! 7. a record with an altered transcript, a missing program or an altered
//!    receipt does not verify.

use std::fs;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use nucleus_receipt::Receipt;
use nucleus_release_gate::body::{
    ApplyOutcome, ApplyReceipt, Approval, Decoding, EvalReceipt, Lineage, Opened, PatchManifest,
    ProposalGrant, ReleaseReceipt, RollbackOrder, RunBudget, SuiteId, open, seal,
};
use nucleus_release_gate::chain::{Head, PointerState, Previous, Refusal, ReleaseChain};
use nucleus_release_gate::eval::{EvalResults, ItemOutcome, Outcome, Thresholds, UnrelatedLimit};
use nucleus_release_gate::keys::{ContentDigest, ReceiptHash, RoleKey};
use nucleus_release_gate::policy::{PolicyParts, ReleasePolicy};
use nucleus_release_gate::registry::Registry;
use nucleus_release_gate::runner::measure;
use nucleus_release_server::app::{Answer, Backend, Reply, Service, router};
use nucleus_release_server::archive::Archive;
use nucleus_release_server::record::{Check, Verdict, verify_record};
use nucleus_release_server::store::CheckpointStore;
use nucleus_weight_patch::{
    Applier, CheckpointDigest, DeclaredWrites, Dtype, Header, Op, PatchProgram, Scalar,
    write_checkpoint,
};
use serde_json::{Value, json};
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// The toy model.
// ---------------------------------------------------------------------------

/// Every tensor of a checkpoint as `f32` values, by name.
fn tensors(files: &[PathBuf]) -> Result<Vec<(String, Vec<f32>)>, String> {
    let mut out = Vec::new();
    for file in files {
        let mut reader = BufReader::new(fs::File::open(file).map_err(|e| e.to_string())?);
        let header = Header::read(&mut reader).map_err(|e| e.to_string())?;
        for (name, info) in header.tensors() {
            let mut bytes = vec![0u8; usize::try_from(info.byte_len()).unwrap()];
            reader.read_exact(&mut bytes).map_err(|e| e.to_string())?;
            let values: Vec<f32> = match info.dtype() {
                Dtype::F32 => bytes
                    .chunks_exact(4)
                    .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                    .collect(),
                Dtype::Bf16 => bytes
                    .chunks_exact(2)
                    .map(|c| f32::from_bits(u32::from_be_bytes([c[1], c[0], 0, 0])))
                    .collect(),
                other => return Err(format!("the toy model does not read {other}")),
            };
            out.push((name.to_owned(), values));
        }
    }
    Ok(out)
}

fn sum(tensors: &[(String, Vec<f32>)], name: &str) -> f32 {
    tensors
        .iter()
        .filter(|(n, _)| n == name)
        .flat_map(|(_, v)| v)
        .sum()
}

/// `math` answers `x` plus the sum of the first bias; `reading` answers `x`
/// plus the sum of the embedding. A patch to the bias moves `math` and leaves
/// `reading` alone; a patch to the embedding does the reverse.
struct Toy;

impl Backend for Toy {
    fn answer(&self, files: &[PathBuf], request: &Value) -> Result<Value, String> {
        let x = request["x"].as_f64().ok_or("the request has no x")?;
        let tensors = tensors(files)?;
        let offset = match request["task"].as_str() {
            Some("math") => sum(&tensors, "layer.0.bias"),
            Some("reading") => sum(&tensors, "embed.weight"),
            _ => return Err("the request names no known task".to_owned()),
        };
        Ok(json!({ "y": x + f64::from(offset) }))
    }
}

/// The sealed suite. A `math` item is right when the answer exceeds `x` by at
/// least the item's bar; the bars run from 2.0 to just under 5.0, so a larger
/// bias gets more of them. A `reading` item is right when the answer is `x`.
fn suite() -> Vec<(&'static str, String, f64, f64)> {
    let math = (0..120u32).map(|i| ("math", format!("m{i}"), 1.0, 2.0 + f64::from(i) / 40.0));
    let reading = (0..60u32).map(|i| ("reading", format!("r{i}"), f64::from(i), 0.0));
    math.chain(reading).collect()
}

fn grade(task: &str, x: f64, bar: f64, answer: &Value) -> bool {
    let y = answer["y"].as_f64().unwrap();
    match task {
        "math" => y - x >= bar,
        _ => (y - x - bar).abs() < 1e-9,
    }
}

// ---------------------------------------------------------------------------
// The parties.
// ---------------------------------------------------------------------------

fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}

fn bf16(values: &[f32]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|v| {
            let [hi, lo, _, _] = v.to_bits().to_be_bytes();
            [lo, hi]
        })
        .collect()
}

fn hash(receipt: &Receipt) -> ReceiptHash {
    receipt.root_hash_hex.parse().unwrap()
}

struct World {
    deployer: SigningKey,
    editor: SigningKey,
    runner: SigningKey,
    evaluator: SigningKey,
    registry_key: RoleKey,
    policy: ReleasePolicy,
    store: CheckpointStore,
    archive: Archive,
    work: PathBuf,
    genesis: CheckpointDigest,
    clock: Arc<AtomicU64>,
    app: Router,
    service: Arc<Service>,
    registry_dir: PathBuf,
}

impl World {
    fn new(root: &Path) -> Self {
        let (deployer, editor, runner, evaluator, registry) =
            (key(1), key(2), key(3), key(4), key(5));
        let policy = ReleasePolicy::new(PolicyParts {
            deployers: vec![RoleKey::of(&deployer)],
            runners: vec![RoleKey::of(&runner)],
            evaluators: vec![RoleKey::of(&evaluator)],
            permitted: DeclaredWrites::new(["layer.0.bias", "layer.1.bias"]).unwrap(),
            suite: SuiteId {
                digest: ContentDigest::from_bytes([9; 32]),
                version: "toy-suite-1".to_owned(),
            },
            decoding: Decoding {
                temperature_milli: 0,
                top_p_milli: 1000,
                top_k: 1,
                max_tokens: 16,
            },
            thresholds: Thresholds {
                target_task: "math".to_owned(),
                min_items: 100,
                min_net_gain_bp: 300,
                max_token_limit_bp: 1000,
                unrelated: vec![UnrelatedLimit {
                    task: "reading".to_owned(),
                    min_items: 50,
                    max_net_loss_bp: 100,
                }],
            },
        })
        .unwrap();

        let work = root.join("work");
        fs::create_dir_all(&work).unwrap();
        let mut bytes = Vec::new();
        write_checkpoint(
            &[
                ("embed.weight", Dtype::F32, &[2], &[0; 8]),
                ("layer.0.bias", Dtype::Bf16, &[2], &bf16(&[1.0, 2.0])),
                ("layer.1.bias", Dtype::Bf16, &[2], &bf16(&[-1.0, 0.25])),
            ],
            &mut bytes,
        )
        .unwrap();
        let genesis_file = work.join("model.bin");
        fs::write(&genesis_file, bytes).unwrap();

        let store = CheckpointStore::open(&root.join("store")).unwrap();
        let archive = Archive::open(&root.join("archive")).unwrap();
        let genesis = store.put(&[genesis_file]).unwrap();
        let registry_dir = root.join("registry");
        let registry_key = RoleKey::of(&registry);
        let registry = Registry::create(
            &registry_dir,
            genesis,
            policy.clone(),
            registry,
            "spiffe://toy.example/registry",
        )
        .unwrap();
        let clock = Arc::new(AtomicU64::new(1_000_000));
        let ticking = Arc::clone(&clock);
        let service = Arc::new(Service::new(
            registry,
            store.clone(),
            Box::new(Toy),
            Box::new(move || ticking.load(Ordering::SeqCst)),
        ));
        Self {
            deployer,
            editor,
            runner,
            evaluator,
            registry_key,
            policy,
            store,
            archive,
            work,
            genesis,
            clock,
            app: router(Arc::clone(&service)),
            service,
            registry_dir,
        }
    }

    /// The present, after letting a little time pass.
    fn tick(&self) -> u64 {
        self.clock.fetch_add(10, Ordering::SeqCst) + 10
    }

    // -- the deployer ------------------------------------------------------

    fn grant(&self, pointer: &PointerState, max_runs: u32) -> Receipt {
        let now = self.tick();
        seal(
            &ProposalGrant {
                editor: RoleKey::of(&self.editor),
                base: pointer.current,
                policy: self.policy.digest(),
                budget: RunBudget {
                    max_runs,
                    max_accelerator_seconds: 3600,
                },
                not_after_micros: now + 1_000_000,
                lineage: match pointer.head {
                    Head::Genesis => Lineage::First,
                    Head::Release { receipt } => Lineage::After { release: receipt },
                },
            },
            &self.deployer,
            "spiffe://toy.example/deployer",
            now,
        )
        .unwrap()
    }

    fn approve(&self, eval: &Receipt, pointer: &PointerState) -> Receipt {
        let now = self.tick();
        let evaluated: Opened<EvalReceipt> = open(eval, RoleKey::of(&self.evaluator)).unwrap();
        seal(
            &Approval {
                eval: evaluated.hash(),
                candidate: evaluated.body().candidate,
                policy: self.policy.digest(),
                generation: pointer.generation,
                not_after_micros: now + 1_000_000,
            },
            &self.deployer,
            "spiffe://toy.example/deployer",
            now,
        )
        .unwrap()
    }

    fn order_rollback(&self, pointer: &PointerState) -> Receipt {
        let now = self.tick();
        let Previous::Checkpoint { digest } = pointer.previous else {
            panic!("nothing is retained");
        };
        seal(
            &RollbackOrder {
                generation: pointer.generation,
                to: digest,
                policy: self.policy.digest(),
                not_after_micros: now + 1_000_000,
            },
            &self.deployer,
            "spiffe://toy.example/deployer",
            now,
        )
        .unwrap()
    }

    // -- the editor --------------------------------------------------------

    /// Proposes adding one half to `writes`, declaring `declared`. The editor
    /// works out the digest it expects by applying its own program to its own
    /// copy of the base.
    fn propose(
        &self,
        grant: &Receipt,
        writes: &[&str],
        declared: &[&str],
    ) -> (Receipt, PatchProgram) {
        let granted: Opened<ProposalGrant> = open(grant, RoleKey::of(&self.deployer)).unwrap();
        let program = PatchProgram::new(
            writes
                .iter()
                .map(|tensor| Op::AddScalar {
                    tensor: (*tensor).to_owned(),
                    value: Scalar::from_f32(0.5).unwrap(),
                })
                .collect(),
        )
        .unwrap();
        let mut applier = Applier::new(&program);
        for file in self.store.measured(granted.body().base).unwrap() {
            applier = applier
                .file(
                    BufReader::new(fs::File::open(file).unwrap()),
                    std::io::sink(),
                )
                .unwrap();
        }
        let expected = applier.finish().unwrap();
        self.archive.put_program(&program).unwrap();
        let manifest = seal(
            &PatchManifest {
                grant: granted.hash(),
                base: granted.body().base,
                program: program.digest(),
                declared: DeclaredWrites::new(declared.iter().copied()).unwrap(),
                expected_output: expected.output().digest(),
            },
            &self.editor,
            "spiffe://toy.example/editor",
            self.tick(),
        )
        .unwrap();
        (manifest, program)
    }

    // -- the runner --------------------------------------------------------

    /// Applies a manifest's program to the base from the store, files the
    /// output in the store, and signs what was measured.
    fn apply(
        &self,
        grant: &Receipt,
        manifest: &Receipt,
        program: &PatchProgram,
        run: u32,
    ) -> Receipt {
        let granted: Opened<ProposalGrant> = open(grant, RoleKey::of(&self.deployer)).unwrap();
        let proposed: Opened<PatchManifest> = open(manifest, granted.body().editor).unwrap();
        let out = self.work.join(format!("run-{}", self.tick()));
        fs::create_dir_all(&out).unwrap();
        let mut applier = Applier::new(program);
        let mut written = Vec::new();
        for file in self.store.measured(proposed.body().base).unwrap() {
            let target = out.join(file.file_name().unwrap());
            applier = applier
                .file(
                    BufReader::new(fs::File::open(&file).unwrap()),
                    fs::File::create(&target).unwrap(),
                )
                .unwrap();
            written.push(target);
        }
        let outcome = measure(proposed.body(), program, applier.finish());
        if let ApplyOutcome::Applied { output, .. } = &outcome {
            assert_eq!(self.store.put(&written).unwrap(), *output);
        }
        seal(
            &ApplyReceipt {
                manifest: proposed.hash(),
                base: proposed.body().base,
                program: proposed.body().program,
                run,
                outcome,
            },
            &self.runner,
            "spiffe://toy.example/runner",
            self.tick(),
        )
        .unwrap()
    }

    // -- the evaluator -----------------------------------------------------

    /// Runs base and candidate over the suite and signs the counts. The
    /// candidate digest in the receipt is the one the evaluator's own read of
    /// the files measured to, not the one the apply receipt claims.
    fn evaluate(&self, apply: &Receipt) -> Receipt {
        let applied: Opened<ApplyReceipt> = open(apply, RoleKey::of(&self.runner)).unwrap();
        let ApplyOutcome::Applied { output, .. } = applied.body().outcome else {
            panic!("there is no candidate to evaluate");
        };
        let base_files = self.store.measured(applied.body().base).unwrap();
        let candidate_files = self.store.measured(output).unwrap();
        let answer = |files: &[PathBuf], task: &str, x: f64, bar: f64| {
            let reply = Toy.answer(files, &json!({ "task": task, "x": x })).unwrap();
            Outcome {
                correct: grade(task, x, bar, &reply),
                token_limit: false,
                output: ContentDigest::from_bytes([u8::from(grade(task, x, bar, &reply)); 32]),
            }
        };
        let outcomes: Vec<ItemOutcome> = suite()
            .into_iter()
            .map(|(task, item, x, bar)| ItemOutcome {
                task: task.to_owned(),
                item,
                seed: 0,
                base: answer(&base_files, task, x, bar),
                candidate: answer(&candidate_files, task, x, bar),
            })
            .collect();
        let transcript = self.archive.put_transcript(&outcomes).unwrap();
        seal(
            &EvalReceipt {
                apply: applied.hash(),
                base: applied.body().base,
                candidate: output,
                suite: self.policy.suite().clone(),
                decoding: self.policy.decoding().clone(),
                seeds: ContentDigest::from_bytes([0; 32]),
                harness: ContentDigest::from_bytes([8; 32]),
                transcript,
                accelerator_seconds: 1,
                results: EvalResults::from_outcomes(&outcomes).unwrap(),
            },
            &self.evaluator,
            "spiffe://toy.example/evaluator",
            self.tick(),
        )
        .unwrap()
    }

    // -- a client of the HTTP surface --------------------------------------

    async fn call(&self, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
            .unwrap();
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    async fn pointer(&self) -> PointerState {
        let (status, body) = self.call("GET", "/v1/pointer", None).await;
        assert_eq!(status, StatusCode::OK);
        serde_json::from_value(body).unwrap()
    }

    /// What the serving endpoint answers to one fixed `math` request.
    async fn served(&self) -> (CheckpointDigest, u64, f64) {
        let (status, body) = self
            .call(
                "POST",
                "/v1/generate",
                Some(json!({ "task": "math", "x": 1.0 })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let answer: Answer = serde_json::from_value(body).unwrap();
        (
            answer.digest,
            answer.generation,
            answer.output["y"].as_f64().unwrap(),
        )
    }

    async fn promote(&self, chain: &ReleaseChain) -> (StatusCode, Reply) {
        self.tick();
        let (status, body) = self
            .call(
                "POST",
                "/v1/promote",
                Some(serde_json::to_value(chain).unwrap()),
            )
            .await;
        (status, serde_json::from_value(body).unwrap())
    }

    async fn refused(&self, chain: &ReleaseChain) -> Refusal {
        match self.promote(chain).await {
            (StatusCode::CONFLICT, Reply::Refused { refusal, .. }) => refusal,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    fn verify(
        &self,
        records_from: &Path,
        archive: &Archive,
    ) -> nucleus_release_server::record::Report {
        let log = fs::read_to_string(records_from).unwrap();
        let records: Vec<_> = log
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        verify_record(
            self.genesis,
            &self.policy,
            self.registry_key,
            &records,
            &self.store,
            archive,
        )
    }
}

/// One proposal taken from grant to evaluation: everything but the approval.
struct Round {
    grant: Receipt,
    manifest: Receipt,
    apply: Receipt,
    eval: Receipt,
}

impl Round {
    fn run(world: &World, grant: Receipt, writes: &[&str], declared: &[&str], run: u32) -> Self {
        let (manifest, program) = world.propose(&grant, writes, declared);
        let apply = world.apply(&grant, &manifest, &program, run);
        let eval = world.evaluate(&apply);
        Self {
            grant,
            manifest,
            apply,
            eval,
        }
    }

    fn chain(&self, approval: Option<Receipt>) -> ReleaseChain {
        ReleaseChain {
            grant: self.grant.clone(),
            manifest: self.manifest.clone(),
            apply: self.apply.clone(),
            eval: self.eval.clone(),
            approval,
        }
    }

    fn candidate(&self, world: &World) -> CheckpointDigest {
        open::<EvalReceipt>(&self.eval, RoleKey::of(&world.evaluator))
            .unwrap()
            .body()
            .candidate
    }
}

// ---------------------------------------------------------------------------
// The workflow.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_release_is_gated_served_replayed_extended_and_rolled_back() {
    let root = tempfile::tempdir().unwrap();
    let world = World::new(root.path());
    let releases = world.registry_dir.join("releases.jsonl");

    // 1. The endpoint serves the genesis checkpoint: 1 + (1 + 2).
    let genesis_pointer = world.pointer().await;
    assert_eq!(world.served().await, (world.genesis, 0, 4.0));

    // The first proposal: add one half to each element of the first bias.
    let grant = world.grant(&genesis_pointer, 3);
    let first = Round::run(
        &world,
        grant.clone(),
        &["layer.0.bias"],
        &["layer.0.bias"],
        1,
    );
    let first_candidate = first.candidate(&world);
    let scored: Opened<EvalReceipt> = open(&first.eval, RoleKey::of(&world.evaluator)).unwrap();
    let math = scored.body().results.task("math").unwrap().clone();
    assert!(
        math.candidate_correct > math.base_correct,
        "it scores higher"
    );
    assert_eq!(
        (math.base_correct, math.candidate_correct, math.regressed),
        (41, 81, 0)
    );

    // 2a. Higher-scoring, and no deployer approved it.
    assert_eq!(
        world.refused(&first.chain(None)).await,
        Refusal::MissingApproval
    );
    assert_eq!(world.served().await, (world.genesis, 0, 4.0));

    // 2b. An evaluation receipt that belongs to a different checkpoint: a
    // genuine, signed evaluation of another candidate, offered for this one,
    // with a genuine approval of that evaluation.
    let other = Round::run(
        &world,
        grant.clone(),
        &["layer.1.bias"],
        &["layer.1.bias"],
        2,
    );
    assert_ne!(other.candidate(&world), first_candidate);
    let mut borrowed = first.chain(Some(world.approve(&other.eval, &genesis_pointer)));
    borrowed.eval = other.eval.clone();
    assert_eq!(
        world.refused(&borrowed).await,
        Refusal::EvalForDifferentCandidate {
            evaluated: other.candidate(&world),
            applied: first_candidate,
        }
    );
    assert_eq!(world.served().await, (world.genesis, 0, 4.0));

    // 2c. A patch that touches a tensor it is not authorized to write. Once
    // declared openly, which the policy refuses; once undeclared, which the
    // runner measures and reports.
    let unauthorized = |refusal: Refusal| match refusal {
        Refusal::UnauthorizedTensorWrite { tensors } => tensors.into_iter().collect::<Vec<_>>(),
        other => panic!("expected an unauthorized write, got {other:?}"),
    };
    let declared = Round::run(
        &world,
        grant.clone(),
        &["layer.0.bias", "embed.weight"],
        &["layer.0.bias", "embed.weight"],
        3,
    );
    let approval = world.approve(&declared.eval, &genesis_pointer);
    assert_eq!(
        unauthorized(world.refused(&declared.chain(Some(approval))).await),
        ["embed.weight"]
    );
    let (manifest, program) =
        world.propose(&grant, &["layer.0.bias", "embed.weight"], &["layer.0.bias"]);
    let apply = world.apply(&grant, &manifest, &program, 3);
    let hidden = ReleaseChain {
        grant: grant.clone(),
        manifest,
        apply,
        // There is no candidate to evaluate; any evaluation stands in, and
        // the walk never reaches it.
        eval: first.eval.clone(),
        approval: None,
    };
    assert_eq!(unauthorized(world.refused(&hidden).await), ["embed.weight"]);
    assert_eq!(world.served().await, (world.genesis, 0, 4.0));
    assert_eq!(world.pointer().await, genesis_pointer);

    // 3. The same first proposal, now approved, is promoted and served.
    let approval = world.approve(&first.eval, &genesis_pointer);
    let (status, reply) = world.promote(&first.chain(Some(approval))).await;
    let Reply::Moved {
        release,
        pointer: after_first,
    } = reply
    else {
        panic!("expected the pointer to move, got {reply:?}");
    };
    assert_eq!(status, StatusCode::OK);
    assert_eq!(after_first.current, first_candidate);
    assert_eq!(
        after_first.previous,
        Previous::Checkpoint {
            digest: world.genesis
        }
    );
    assert_eq!(world.served().await, (first_candidate, 1, 5.0));
    let released: Opened<ReleaseReceipt> = open(&release, world.registry_key).unwrap();
    assert_eq!(
        after_first.head,
        Head::Release {
            receipt: released.hash()
        }
    );

    // The approval moved the pointer once. Offered again, it moves nothing.
    assert!(matches!(
        world
            .refused(&first.chain(Some(world.approve(&first.eval, &genesis_pointer))))
            .await,
        Refusal::BaseNotCurrent { .. }
    ));

    // 4. A verifier with only files replays the patch to the same digest.
    let report = world.verify(&releases, &world.archive);
    assert_eq!(report.verdict, Verdict::Verified, "{report:?}");
    assert_eq!(report.pointer, Some(after_first));
    let [check] = report.promotions.as_slice() else {
        panic!("one promotion so far");
    };
    assert_eq!(check.candidate, first_candidate);
    assert_eq!(
        (&check.patch, &check.scores),
        (&Check::Verified, &Check::Verified)
    );

    // 5. A second round, with the promoted checkpoint as the base. The first
    // round's grant does not carry over.
    let stale = Round::run(&world, grant, &["layer.0.bias"], &["layer.0.bias"], 3);
    let approval = world.approve(&stale.eval, &after_first);
    assert!(matches!(
        world.refused(&stale.chain(Some(approval))).await,
        Refusal::BaseNotCurrent { .. }
    ));
    let fresh_grant = world.grant(&after_first, 1);
    let granted: Opened<ProposalGrant> = open(&fresh_grant, RoleKey::of(&world.deployer)).unwrap();
    assert_eq!(granted.body().base, first_candidate);
    assert_eq!(
        granted.body().lineage,
        Lineage::After {
            release: hash(&release)
        }
    );
    let second = Round::run(&world, fresh_grant, &["layer.0.bias"], &["layer.0.bias"], 1);
    let approval = world.approve(&second.eval, &after_first);
    let (status, reply) = world.promote(&second.chain(Some(approval))).await;
    let Reply::Moved {
        pointer: after_second,
        ..
    } = reply
    else {
        panic!("expected the pointer to move, got {reply:?}");
    };
    assert_eq!(status, StatusCode::OK);
    let second_candidate = second.candidate(&world);
    assert_eq!(world.served().await, (second_candidate, 2, 6.0));
    assert_eq!(
        after_second.previous,
        Previous::Checkpoint {
            digest: first_candidate
        }
    );

    // 6. Rollback returns the endpoint to the previous checkpoint.
    let order = world.order_rollback(&after_second);
    world.tick();
    let (status, body) = world
        .call(
            "POST",
            "/v1/rollback",
            Some(serde_json::to_value(&order).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let Reply::Moved {
        pointer: after_rollback,
        ..
    } = serde_json::from_value(body).unwrap()
    else {
        panic!("expected the pointer to move");
    };
    assert_eq!(world.served().await, (first_candidate, 3, 5.0));
    assert_eq!(
        after_rollback.previous,
        Previous::Checkpoint {
            digest: second_candidate
        }
    );

    // The whole record still verifies: two promotions and a rollback.
    let report = world.verify(&releases, &world.archive);
    assert_eq!(report.verdict, Verdict::Verified, "{report:?}");
    assert_eq!(report.pointer, Some(after_rollback));
    assert_eq!(report.promotions.len(), 2);
    let (status, log) = world.call("GET", "/v1/releases", None).await;
    assert_eq!((status, log.as_array().unwrap().len()), (StatusCode::OK, 3));

    // 7. Tamper controls, each on a copy of the record.
    let copy = |name: &str| {
        let dir = root.path().join(name);
        fs::create_dir_all(dir.join("programs")).unwrap();
        fs::create_dir_all(dir.join("transcripts")).unwrap();
        for sub in ["programs", "transcripts"] {
            for entry in fs::read_dir(root.path().join("archive").join(sub)).unwrap() {
                let entry = entry.unwrap();
                fs::copy(entry.path(), dir.join(sub).join(entry.file_name())).unwrap();
            }
        }
        dir
    };
    let transcript_of = |round: &Round| {
        open::<EvalReceipt>(&round.eval, RoleKey::of(&world.evaluator))
            .unwrap()
            .body()
            .transcript
            .to_hex()
    };

    // An altered transcript: one answer regraded.
    let dir = copy("altered-transcript");
    let path = dir
        .join("transcripts")
        .join(format!("{}.jsonl", transcript_of(&first)));
    let text = fs::read_to_string(&path).unwrap();
    fs::write(
        &path,
        text.replacen("\"correct\":false", "\"correct\":true", 1),
    )
    .unwrap();
    let report = world.verify(&releases, &Archive::open(&dir).unwrap());
    assert_eq!(report.verdict, Verdict::Refuted);
    assert!(matches!(report.promotions[0].scores, Check::Refuted { .. }));
    assert_eq!(report.promotions[0].patch, Check::Verified);

    // A missing program: the patch cannot be replayed, and that is not a pass.
    let dir = copy("missing-program");
    for entry in fs::read_dir(dir.join("programs")).unwrap() {
        fs::remove_file(entry.unwrap().path()).unwrap();
    }
    let report = world.verify(&releases, &Archive::open(&dir).unwrap());
    assert_eq!(report.verdict, Verdict::CouldNotLook);
    assert!(matches!(
        report.promotions[0].patch,
        Check::CouldNotLook { .. }
    ));
    assert_eq!(report.promotions[0].scores, Check::Verified);

    // An altered program: the bytes under the digest are another program.
    let dir = copy("altered-program");
    for entry in fs::read_dir(dir.join("programs")).unwrap() {
        let path = entry.unwrap().path();
        let text = fs::read_to_string(&path).unwrap();
        fs::write(&path, text.replace("0x3f000000", "0x3f800000")).unwrap();
    }
    let report = world.verify(&releases, &Archive::open(&dir).unwrap());
    assert_eq!(report.verdict, Verdict::Refuted);

    // An altered receipt in the log.
    let altered_log = root.path().join("altered-releases.jsonl");
    let log = fs::read_to_string(&releases).unwrap();
    fs::write(&altered_log, log.replacen("\"run\":1", "\"run\":2", 1)).unwrap();
    let report = world.verify(&altered_log, &world.archive);
    assert_eq!(report.verdict, Verdict::Refuted);
    assert!(matches!(report.chain, Check::Refuted { .. }));
    assert_eq!(report.pointer, None);
}

#[tokio::test]
async fn files_that_no_longer_measure_to_the_pointer_are_not_served() {
    let root = tempfile::tempdir().unwrap();
    let world = World::new(root.path());
    assert_eq!(world.served().await.0, world.genesis);

    // Replace the stored genesis file with another valid checkpoint, and
    // start a second service over the same registry and store: it has
    // nothing loaded, so it must measure before it answers.
    let filed = world.store.measured(world.genesis).unwrap();
    let mut other = Vec::new();
    write_checkpoint(
        &[
            ("embed.weight", Dtype::F32, &[2], &[0; 8]),
            ("layer.0.bias", Dtype::Bf16, &[2], &bf16(&[9.0, 9.0])),
            ("layer.1.bias", Dtype::Bf16, &[2], &bf16(&[-1.0, 0.25])),
        ],
        &mut other,
    )
    .unwrap();
    fs::write(&filed[0], other).unwrap();
    let registry = Registry::open(
        &world.registry_dir,
        world.policy.clone(),
        key(5),
        "spiffe://toy.example/registry",
    )
    .unwrap();
    let second = router(Arc::new(Service::new(
        registry,
        world.store.clone(),
        Box::new(Toy),
        Box::new(|| 2_000_000),
    )));
    let response = second
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/generate")
                .header("content-type", "application/json")
                .body(Body::from(json!({ "task": "math", "x": 1.0 }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    // The first service is unused from here; it is kept alive so the two
    // share nothing but the directories.
    drop(world.service);
}

/// The gate takes two things on a role's word: that the runner's output
/// digest is what the program produces, and that the evaluator's counts are
/// the counts of its transcript. A verifier with the files takes neither.
#[tokio::test]
async fn a_misreported_output_and_inflated_scores_pass_the_gate_and_fail_replay() {
    let root = tempfile::tempdir().unwrap();
    let world = World::new(root.path());
    let releases = world.registry_dir.join("releases.jsonl");
    let pointer = world.pointer().await;
    let grant = world.grant(&pointer, 2);
    let granted: Opened<ProposalGrant> = open(&grant, RoleKey::of(&world.deployer)).unwrap();

    // A different checkpoint that really exists: the second bias patched.
    let decoy = Round::run(
        &world,
        grant.clone(),
        &["layer.1.bias"],
        &["layer.1.bias"],
        1,
    );
    let decoy_digest = decoy.candidate(&world);

    // The editor names the decoy as the output of a program that patches the
    // first bias, and a colluding runner signs that it was so.
    let (honest_manifest, program) = world.propose(&grant, &["layer.0.bias"], &["layer.0.bias"]);
    let honest_apply = world.apply(&grant, &honest_manifest, &program, 2);
    let honest: Opened<ApplyReceipt> = open(&honest_apply, RoleKey::of(&world.runner)).unwrap();
    let ApplyOutcome::Applied { writes, .. } = honest.body().outcome.clone() else {
        panic!("the honest application succeeds");
    };
    let manifest = seal(
        &PatchManifest {
            grant: granted.hash(),
            base: world.genesis,
            program: program.digest(),
            declared: DeclaredWrites::new(["layer.0.bias"]).unwrap(),
            expected_output: decoy_digest,
        },
        &world.editor,
        "spiffe://toy.example/editor",
        world.tick(),
    )
    .unwrap();
    let apply = seal(
        &ApplyReceipt {
            manifest: hash(&manifest),
            base: world.genesis,
            program: program.digest(),
            run: 2,
            outcome: ApplyOutcome::Applied {
                output: decoy_digest,
                writes,
            },
        },
        &world.runner,
        "spiffe://toy.example/runner",
        world.tick(),
    )
    .unwrap();

    // The evaluator binds an honest transcript of the decoy, which shows no
    // gain, and signs counts computed from a better one.
    let real: Opened<EvalReceipt> =
        open(&world.evaluate(&apply), RoleKey::of(&world.evaluator)).unwrap();
    let mut inflated = world.archive.transcript(real.body().transcript).unwrap();
    for outcome in inflated.iter_mut().filter(|o| o.task == "math") {
        outcome.candidate.correct = true;
    }
    let mut body = real.body().clone();
    body.results = EvalResults::from_outcomes(&inflated).unwrap();
    let eval = seal(
        &body,
        &world.evaluator,
        "spiffe://toy.example/evaluator",
        world.tick(),
    )
    .unwrap();

    let approval = world.approve(&eval, &pointer);
    let chain = ReleaseChain {
        grant,
        manifest,
        apply,
        eval,
        approval: Some(approval),
    };
    let (status, reply) = world.promote(&chain).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "every signature is genuine: {reply:?}"
    );

    let report = world.verify(&releases, &world.archive);
    assert_eq!(report.verdict, Verdict::Refuted);
    assert_eq!(report.chain, Check::Verified, "the chain itself is intact");
    assert!(matches!(report.promotions[0].patch, Check::Refuted { .. }));
    assert!(matches!(report.promotions[0].scores, Check::Refuted { .. }));
}

#[tokio::test]
async fn a_candidate_the_store_cannot_produce_is_not_promoted() {
    let root = tempfile::tempdir().unwrap();
    let world = World::new(root.path());
    let pointer = world.pointer().await;
    let round = Round::run(
        &world,
        world.grant(&pointer, 1),
        &["layer.0.bias"],
        &["layer.0.bias"],
        1,
    );
    let approval = world.approve(&round.eval, &pointer);
    // The chain is complete and valid. The files are gone.
    fs::remove_dir_all(
        root.path()
            .join("store")
            .join(round.candidate(&world).to_hex()),
    )
    .unwrap();

    let (status, reply) = world.promote(&round.chain(Some(approval))).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(matches!(reply, Reply::CouldNotLook { .. }), "{reply:?}");
    assert_eq!(world.pointer().await, pointer);
    assert_eq!(world.served().await, (world.genesis, 0, 4.0));
}
