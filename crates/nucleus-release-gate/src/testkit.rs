//! A small world for tests: five keys, a policy, a toy checkpoint, and an
//! honest chain whose bodies a test can change before they are signed.

use ed25519_dalek::SigningKey;
use nucleus_weight_patch::{
    Applier, CheckpointDigest, DeclaredWrites, Dtype, Indexer, Op, PatchProgram, Scalar,
    write_checkpoint,
};

use crate::body::{
    ApplyReceipt, Approval, Decoding, EvalReceipt, Lineage, PatchManifest, ProposalGrant,
    RunBudget, SuiteId, seal,
};
use crate::chain::{Head, PointerState, ReleaseChain};
use crate::eval::{
    EvalResults, ItemOutcome, Outcome, Thresholds, UnrelatedLimit, transcript_digest,
};
use crate::keys::{ContentDigest, ReceiptHash, RoleKey};
use crate::policy::{PolicyParts, ReleasePolicy};
use crate::runner::measure;

/// The moment tests decide at.
pub(crate) const NOW: u64 = 1_000_000;

pub(crate) fn key(n: u8) -> SigningKey {
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

/// `n` paired answers on `task`: the base right on the first `base`, the
/// candidate right on the first `candidate` and out of tokens on the last
/// `limit`.
pub(crate) fn outcomes(
    task: &str,
    n: u64,
    base: u64,
    candidate: u64,
    limit: u64,
) -> Vec<ItemOutcome> {
    let answer = |correct: bool, token_limit: bool| Outcome {
        correct,
        token_limit,
        output: ContentDigest::from_bytes([u8::from(correct); 32]),
    };
    (0..n)
        .map(|i| ItemOutcome {
            task: task.to_owned(),
            item: format!("item-{i}"),
            seed: 7,
            base: answer(i < base, false),
            candidate: answer(i < candidate, i >= n - limit),
        })
        .collect()
}

pub(crate) struct World {
    pub deployer: SigningKey,
    pub editor: SigningKey,
    pub runner: SigningKey,
    pub evaluator: SigningKey,
    pub registry: SigningKey,
    pub policy: ReleasePolicy,
    /// The checkpoint a registry in this world starts from.
    pub genesis_file: Vec<u8>,
}

impl World {
    pub(crate) fn new() -> Self {
        let mut genesis_file = Vec::new();
        write_checkpoint(
            &[
                ("embed.weight", Dtype::F32, &[2], &[0; 8]),
                ("layer.0.bias", Dtype::Bf16, &[2], &bf16(&[1.0, 2.0])),
                ("layer.1.bias", Dtype::Bf16, &[2], &bf16(&[-1.0, 0.25])),
            ],
            &mut genesis_file,
        )
        .unwrap();
        let (deployer, runner, evaluator) = (key(1), key(3), key(4));
        let policy = ReleasePolicy::new(parts_for(&deployer, &runner, &evaluator)).unwrap();
        Self {
            deployer,
            editor: key(2),
            runner,
            evaluator,
            registry: key(5),
            policy,
            genesis_file,
        }
    }

    pub(crate) fn parts(&self) -> PolicyParts {
        parts_for(&self.deployer, &self.runner, &self.evaluator)
    }

    pub(crate) fn genesis(&self) -> CheckpointDigest {
        digest_of(&self.genesis_file)
    }
}

fn parts_for(deployer: &SigningKey, runner: &SigningKey, evaluator: &SigningKey) -> PolicyParts {
    PolicyParts {
        deployers: vec![RoleKey::of(deployer)],
        runners: vec![RoleKey::of(runner)],
        evaluators: vec![RoleKey::of(evaluator)],
        permitted: DeclaredWrites::new(["layer.0.bias", "layer.1.bias"]).unwrap(),
        suite: SuiteId {
            digest: ContentDigest::from_bytes([9; 32]),
            version: "suite-1".to_owned(),
        },
        decoding: Decoding {
            temperature_milli: 600,
            top_p_milli: 950,
            top_k: 20,
            max_tokens: 16_384,
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
    }
}

pub(crate) fn digest_of(file: &[u8]) -> CheckpointDigest {
    Indexer::start().file(file).unwrap().finish().digest()
}

pub(crate) fn add_half(tensors: &[&str]) -> PatchProgram {
    PatchProgram::new(
        tensors
            .iter()
            .map(|tensor| Op::AddScalar {
                tensor: (*tensor).to_owned(),
                value: Scalar::from_f32(0.5).unwrap(),
            })
            .collect(),
    )
    .unwrap()
}

/// Who signs each hop. A test replaces one to model a key in the wrong hands.
pub(crate) struct Signers {
    pub grant: SigningKey,
    pub manifest: SigningKey,
    pub apply: SigningKey,
    pub eval: SigningKey,
    pub approval: SigningKey,
}

/// An honest chain, unsigned. Every body is the one an honest party would
/// write; a test changes what its scenario needs and calls [`Draft::sign`],
/// which fills in each citation of the hop before it.
pub(crate) struct Draft {
    pub grant: ProposalGrant,
    pub manifest: PatchManifest,
    pub apply: ApplyReceipt,
    pub eval: EvalReceipt,
    pub approval: Option<Approval>,
    pub signers: Signers,
    /// The patched checkpoint file.
    pub output_file: Vec<u8>,
}

impl Draft {
    /// The chain for adding one half to `writes` in `base_file`, declared as
    /// `declared`, against `pointer`.
    pub(crate) fn honest(
        world: &World,
        pointer: &PointerState,
        base_file: &[u8],
        writes: &[&str],
        declared: &[&str],
    ) -> Self {
        let nothing = ReceiptHash::from_bytes([0; 32]);
        let program = add_half(writes);
        let mut output_file = Vec::new();
        let applied = Applier::new(&program)
            .file(base_file, &mut output_file)
            .unwrap()
            .finish()
            .unwrap();
        let base = applied.base().digest();
        let candidate = applied.output().digest();

        let grant = ProposalGrant {
            editor: RoleKey::of(&world.editor),
            base,
            policy: world.policy.digest(),
            budget: RunBudget {
                max_runs: 1,
                max_accelerator_seconds: 3600,
            },
            not_after_micros: NOW + 1000,
            lineage: match pointer.head {
                Head::Genesis => Lineage::First,
                Head::Release { receipt } => Lineage::After { release: receipt },
            },
        };
        let manifest = PatchManifest {
            grant: nothing,
            base,
            program: program.digest(),
            declared: DeclaredWrites::new(declared.iter().copied()).unwrap(),
            expected_output: candidate,
        };
        let apply = ApplyReceipt {
            manifest: nothing,
            base,
            program: program.digest(),
            run: 1,
            outcome: measure(&manifest, &program, Ok(applied)),
        };
        let mut transcript = outcomes("math", 200, 100, 120, 4);
        transcript.extend(outcomes("reading", 100, 80, 80, 0));
        let eval = EvalReceipt {
            apply: nothing,
            base,
            candidate,
            suite: world.policy.suite().clone(),
            decoding: world.policy.decoding().clone(),
            seeds: ContentDigest::from_bytes([7; 32]),
            harness: ContentDigest::from_bytes([8; 32]),
            transcript: transcript_digest(&transcript).unwrap(),
            accelerator_seconds: 600,
            results: EvalResults::from_outcomes(&transcript).unwrap(),
        };
        let approval = Approval {
            eval: nothing,
            candidate,
            policy: world.policy.digest(),
            generation: pointer.generation,
            not_after_micros: NOW + 1000,
        };
        Self {
            grant,
            manifest,
            apply,
            eval,
            approval: Some(approval),
            signers: Signers {
                grant: world.deployer.clone(),
                manifest: world.editor.clone(),
                apply: world.runner.clone(),
                eval: world.evaluator.clone(),
                approval: world.deployer.clone(),
            },
            output_file,
        }
    }

    /// Replaces the evaluation's results with ones computed from `transcript`.
    pub(crate) fn with_transcript(mut self, transcript: &[ItemOutcome]) -> Self {
        self.eval.transcript = transcript_digest(transcript).unwrap();
        self.eval.results = EvalResults::from_outcomes(transcript).unwrap();
        self
    }

    /// Signs every hop, each citing the one before it.
    pub(crate) fn sign(&self) -> ReleaseChain {
        let hash = |receipt: &nucleus_receipt::Receipt| -> ReceiptHash {
            receipt.root_hash_hex.parse().unwrap()
        };
        let grant = seal(
            &self.grant,
            &self.signers.grant,
            "spiffe://test/deployer",
            NOW - 40,
        )
        .unwrap();
        let mut manifest = self.manifest.clone();
        manifest.grant = hash(&grant);
        let manifest = seal(
            &manifest,
            &self.signers.manifest,
            "spiffe://test/editor",
            NOW - 30,
        )
        .unwrap();
        let mut apply = self.apply.clone();
        apply.manifest = hash(&manifest);
        let apply = seal(
            &apply,
            &self.signers.apply,
            "spiffe://test/runner",
            NOW - 20,
        )
        .unwrap();
        let mut eval = self.eval.clone();
        eval.apply = hash(&apply);
        let eval = seal(
            &eval,
            &self.signers.eval,
            "spiffe://test/evaluator",
            NOW - 10,
        )
        .unwrap();
        let approval = self.approval.clone().map(|mut approval| {
            approval.eval = hash(&eval);
            seal(
                &approval,
                &self.signers.approval,
                "spiffe://test/deployer",
                NOW - 5,
            )
            .unwrap()
        });
        ReleaseChain {
            grant,
            manifest,
            apply,
            eval,
            approval,
        }
    }
}
