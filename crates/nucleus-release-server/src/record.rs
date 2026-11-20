//! Verifying a release record from files: the chain, the patch, the scores.
//!
//! Three things are checked, and each has three answers.
//!
//! - **The chain.** The release log is replayed from the genesis digest under
//!   the policy and the registry's public key
//!   ([`nucleus_release_gate::registry::audit_steps`]).
//! - **The patch**, for each promotion. The program the manifest names is
//!   applied to the base it names, and the result must be the candidate.
//! - **The scores**, for each promotion. The results the evaluator signed
//!   must be the results of the transcript it bound.
//!
//! "Could not look" is its own answer: a program, transcript or base that is
//! not there to check is not a pass. Material that is there but is not what
//! the receipt names — a file under a digest it does not have — refutes the
//! record as presented.

use std::fs::File;
use std::io::{self, BufReader};

use nucleus_release_gate::chain::{ChainFacts, PointerState};
use nucleus_release_gate::eval::EvalResults;
use nucleus_release_gate::keys::RoleKey;
use nucleus_release_gate::policy::ReleasePolicy;
use nucleus_release_gate::registry::{AuditStep, ReleaseRecord, Replayed, audit_steps};
use nucleus_weight_patch::{Applier, CheckpointDigest};
use serde::Serialize;

use crate::archive::{Archive, ArchiveError};
use crate::store::{CheckpointStore, StoreError};

/// The answer to one check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "check", rename_all = "snake_case")]
pub enum Check {
    /// The check was made and held.
    Verified,
    /// The check was made and did not hold.
    Refuted {
        /// What did not hold.
        detail: String,
    },
    /// The check could not be made.
    CouldNotLook {
        /// What was missing.
        detail: String,
    },
}

/// The checks on one promotion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PromotionCheck {
    /// The pointer generation the promotion produced.
    pub generation: u64,
    /// The candidate it promoted.
    pub candidate: CheckpointDigest,
    /// Whether replaying the patch recovers the candidate.
    pub patch: Check,
    /// Whether the signed results are the results of the bound transcript.
    pub scores: Check,
}

/// The overall answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Every check was made and held.
    Verified,
    /// At least one check was made and did not hold.
    Refuted,
    /// No check failed, and at least one could not be made.
    CouldNotLook,
}

/// Everything that was checked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Report {
    /// The overall answer.
    pub verdict: Verdict,
    /// Whether the release log replays.
    pub chain: Check,
    /// The pointer the log leads to, if it replays.
    pub pointer: Option<PointerState>,
    /// One entry per promotion in the log.
    pub promotions: Vec<PromotionCheck>,
}

fn could_not_look(detail: impl ToString) -> Check {
    Check::CouldNotLook {
        detail: detail.to_string(),
    }
}

fn refuted(detail: impl ToString) -> Check {
    Check::Refuted {
        detail: detail.to_string(),
    }
}

fn archive_failure(error: &ArchiveError) -> Check {
    match error {
        ArchiveError::Absent { .. } | ArchiveError::Io(_) => could_not_look(error),
        ArchiveError::Malformed { .. }
        | ArchiveError::Mismatch { .. }
        | ArchiveError::Outcome(_) => refuted(error),
    }
}

fn store_failure(error: &StoreError) -> Check {
    match error {
        StoreError::Absent { .. } | StoreError::Io(_) => could_not_look(error),
        StoreError::NotACheckpoint(_)
        | StoreError::Mismatch { .. }
        | StoreError::Unnamed { .. } => refuted(error),
    }
}

/// Applies the program the chain names to the base it names and compares the
/// result with the candidate.
fn replay_patch(facts: &ChainFacts, store: &CheckpointStore, archive: &Archive) -> Check {
    let program = match archive.program(facts.program()) {
        Ok(program) => program,
        Err(e) => return archive_failure(&e),
    };
    let files = match store.measured(facts.base()) {
        Ok(files) => files,
        Err(e) => return store_failure(&e),
    };
    let mut applier = Applier::new(&program);
    for file in &files {
        let reader = match File::open(file) {
            Ok(opened) => BufReader::new(opened),
            Err(e) => return could_not_look(e),
        };
        applier = match applier.file(reader, io::sink()) {
            Ok(applier) => applier,
            Err(e) => return refuted(e),
        };
    }
    match applier.finish() {
        Ok(applied) if applied.output().digest() == facts.candidate() => Check::Verified,
        Ok(applied) => refuted(format!(
            "replaying the program gives {}; the record's candidate is {}",
            applied.output().digest(),
            facts.candidate()
        )),
        Err(e) => refuted(e),
    }
}

/// Recomputes the results from the transcript the evaluation bound.
fn recompute_scores(facts: &ChainFacts, archive: &Archive) -> Check {
    let outcomes = match archive.transcript(facts.transcript()) {
        Ok(outcomes) => outcomes,
        Err(e) => return archive_failure(&e),
    };
    match EvalResults::from_outcomes(&outcomes) {
        Ok(results) if results == *facts.results() => Check::Verified,
        Ok(_) => refuted("the signed results are not the results of the bound transcript"),
        Err(e) => refuted(e),
    }
}

/// Verifies a release record.
///
/// Takes public material only: the genesis digest, the policy, the registry's
/// public key, the log's records, and the directories holding the checkpoints
/// and the archived programs and transcripts.
#[must_use]
pub fn verify_record(
    genesis: CheckpointDigest,
    policy: &ReleasePolicy,
    registry: RoleKey,
    records: &[ReleaseRecord],
    store: &CheckpointStore,
    archive: &Archive,
) -> Report {
    let steps = match audit_steps(genesis, policy, registry, records) {
        Ok(steps) => steps,
        Err(e) => {
            return Report {
                verdict: Verdict::Refuted,
                chain: refuted(e),
                pointer: None,
                promotions: Vec::new(),
            };
        }
    };
    let pointer = steps
        .last()
        .map_or_else(|| PointerState::genesis(genesis), |step| step.pointer);
    let mut promotions = Vec::new();
    for step in &steps {
        let AuditStep { pointer, replayed } = step;
        match replayed {
            Replayed::Promotion(facts) => promotions.push(PromotionCheck {
                generation: pointer.generation,
                candidate: facts.candidate(),
                patch: replay_patch(facts, store, archive),
                scores: recompute_scores(facts, archive),
            }),
            Replayed::Rollback => {}
        }
    }
    let checks = || promotions.iter().flat_map(|p| [&p.patch, &p.scores]);
    let verdict = if checks().any(|c| matches!(c, Check::Refuted { .. })) {
        Verdict::Refuted
    } else if checks().any(|c| matches!(c, Check::CouldNotLook { .. })) {
        Verdict::CouldNotLook
    } else {
        Verdict::Verified
    };
    Report {
        verdict,
        chain: Check::Verified,
        pointer: Some(pointer),
        promotions,
    }
}
