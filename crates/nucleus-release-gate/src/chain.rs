//! The chain walk: five receipts, checked hop by hop against the policy and
//! the pointer, yielding either the right to move the pointer once or the
//! first reason it may not move.
//!
//! Every key a receipt is verified under comes from the policy, or from a
//! receipt already verified (the grant names the editor). Each hop is bound to
//! the one before it by root hash. A refusal names the hop.

use std::collections::BTreeSet;

use nucleus_receipt::Receipt;
use nucleus_weight_patch::{CheckpointDigest, ProgramDigest};
use serde::{Deserialize, Serialize};

use crate::body::{
    ApplyOutcome, ApplyReceipt, Approval, Body, EvalReceipt, Lineage, OpenError, Opened,
    PatchManifest, ProposalGrant, RollbackOrder, Transition, named_issuer, open,
};
use crate::eval::{EvalResults, ThresholdFailure, check_thresholds};
use crate::keys::{ContentDigest, ReceiptHash, RoleKey};
use crate::policy::ReleasePolicy;

/// What the pointer retains for rollback.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "previous", rename_all = "snake_case", deny_unknown_fields)]
pub enum Previous {
    /// Nothing: the pointer has never moved.
    Nothing,
    /// The checkpoint served before the current one.
    Checkpoint {
        /// Its digest.
        digest: CheckpointDigest,
    },
}

/// What put the current checkpoint in place.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "head", rename_all = "snake_case", deny_unknown_fields)]
pub enum Head {
    /// The registry was created with it.
    Genesis,
    /// This release or rollback receipt.
    Release {
        /// The receipt.
        receipt: ReceiptHash,
    },
}

/// The serving pointer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PointerState {
    /// The checkpoint being served.
    pub current: CheckpointDigest,
    /// The checkpoint retained for rollback.
    pub previous: Previous,
    /// How many times the pointer has moved.
    pub generation: u64,
    /// What put `current` in place.
    pub head: Head,
}

impl PointerState {
    /// The pointer of a registry created with `digest`.
    #[must_use]
    pub const fn genesis(digest: CheckpointDigest) -> Self {
        Self {
            current: digest,
            previous: Previous::Nothing,
            generation: 0,
            head: Head::Genesis,
        }
    }
}

/// The evidence offered for one promotion.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseChain {
    /// The proposal grant.
    pub grant: Receipt,
    /// The patch manifest.
    pub manifest: Receipt,
    /// The apply receipt.
    pub apply: Receipt,
    /// The evaluation receipt.
    pub eval: Receipt,
    /// The approval, if one was given. Its absence refuses the promotion.
    pub approval: Option<Receipt>,
}

/// A position in the chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Hop {
    /// The proposal grant.
    Grant,
    /// The patch manifest.
    Manifest,
    /// The apply receipt.
    Apply,
    /// The evaluation receipt.
    Eval,
    /// The approval.
    Approval,
    /// The rollback order.
    RollbackOrder,
}

/// Why the pointer may not move.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "refusal", rename_all = "snake_case", deny_unknown_fields)]
pub enum Refusal {
    /// A receipt names an issuer the policy does not give that role.
    #[error("the {hop:?} receipt is not signed by a key that holds the role")]
    UntrustedSigner {
        /// The hop.
        hop: Hop,
    },
    /// A receipt did not verify or did not hold the expected body.
    #[error("the {hop:?} receipt was not accepted: {error}")]
    BadReceipt {
        /// The hop.
        hop: Hop,
        /// Why.
        error: OpenError,
    },
    /// A receipt is dated after the moment of decision.
    #[error("the {hop:?} receipt is dated in the future")]
    IssuedInFuture {
        /// The hop.
        hop: Hop,
    },
    /// A receipt was issued under a different policy.
    #[error("the {hop:?} receipt was issued under a different policy")]
    PolicyMismatch {
        /// The hop.
        hop: Hop,
    },
    /// The grant is for a checkpoint that is not the one being served.
    #[error("the grant is for base {claimed}; the checkpoint being served is {current}")]
    BaseNotCurrent {
        /// The base the grant names.
        claimed: CheckpointDigest,
        /// The checkpoint being served.
        current: CheckpointDigest,
    },
    /// The grant does not cite the release that put its base in place.
    #[error("the grant does not cite the release that put its base in place")]
    LineageMismatch,
    /// The grant has expired.
    #[error("the grant has expired")]
    GrantExpired,
    /// The grant names an editor key that also holds a policy role.
    #[error("the editor's key also holds a role in the policy")]
    EditorHoldsRole,
    /// A receipt does not cite the receipt before it.
    #[error("the {hop:?} receipt does not cite the receipt before it")]
    BrokenLink {
        /// The hop whose citation is wrong.
        hop: Hop,
    },
    /// A receipt disagrees with an earlier one about a value both carry.
    #[error("the {hop:?} receipt disagrees with the chain about {field}")]
    Inconsistent {
        /// The hop.
        hop: Hop,
        /// The value they disagree about.
        field: String,
    },
    /// The patch declares, or wrote, a tensor outside what is allowed.
    #[error("the patch touches tensors it is not authorized to write: {tensors:?}")]
    UnauthorizedTensorWrite {
        /// The tensors.
        tensors: BTreeSet<String>,
    },
    /// The runner reports that the program could not be applied.
    #[error("the runner could not apply the program: {reason}")]
    NotApplied {
        /// The runner's reason.
        reason: String,
    },
    /// The program produced a checkpoint other than the one the manifest
    /// expects.
    #[error("the program produced {actual}; the manifest expects {expected}")]
    OutputMismatch {
        /// What the manifest expects.
        expected: CheckpointDigest,
        /// What was produced.
        actual: CheckpointDigest,
    },
    /// The work exceeded the grant's budget.
    #[error("the grant's budget for {what} is exceeded")]
    BudgetExceeded {
        /// Which budget.
        what: String,
    },
    /// The evaluation measured a checkpoint other than the one applied.
    #[error("the evaluation measured {evaluated}; the applied candidate is {applied}")]
    EvalForDifferentCandidate {
        /// The checkpoint the evaluation measured.
        evaluated: CheckpointDigest,
        /// The checkpoint the runner produced.
        applied: CheckpointDigest,
    },
    /// The evaluation used a suite or decoding settings other than the
    /// policy's.
    #[error("the evaluation did not use the policy's suite and decoding settings")]
    EvalConfigMismatch,
    /// The evaluation does not meet a threshold.
    #[error("the evaluation does not meet the policy: {failure}")]
    ThresholdNotMet {
        /// Which one.
        failure: ThresholdFailure,
    },
    /// No approval was offered.
    #[error("no approval was offered")]
    MissingApproval,
    /// The approval is signed with the editor's key.
    #[error("the approval is signed by the editor")]
    ApproverNotDistinct,
    /// The approval, or rollback order, is for another candidate or target.
    #[error("the {hop:?} receipt is for a different checkpoint")]
    ForDifferentCheckpoint {
        /// The hop.
        hop: Hop,
    },
    /// The approval, or rollback order, is for a pointer generation that is
    /// not the current one.
    #[error("the {hop:?} receipt is for generation {approved}; the pointer is at {current}")]
    StaleGeneration {
        /// The hop.
        hop: Hop,
        /// The generation the receipt names.
        approved: u64,
        /// The pointer's generation.
        current: u64,
    },
    /// The approval, or rollback order, has expired.
    #[error("the {hop:?} receipt has expired")]
    Expired {
        /// The hop.
        hop: Hop,
    },
    /// There is no previous checkpoint to return to.
    #[error("the pointer retains no previous checkpoint")]
    NothingToRollBackTo,
}

/// The right to move the pointer once: from one checkpoint to another, at one
/// generation, until a deadline.
///
/// Minted only by [`verify_chain`] and [`verify_rollback`]. It cannot be
/// cloned or built from parts, and the registry takes it by value.
#[derive(Debug)]
#[must_use = "a move that is never applied is a release that was approved and not made"]
pub struct PointerMove {
    pub(crate) from: CheckpointDigest,
    pub(crate) to: CheckpointDigest,
    pub(crate) generation: u64,
    pub(crate) not_after: u64,
    pub(crate) transition: Transition,
}

impl PointerMove {
    /// The checkpoint the pointer must be at.
    pub const fn source(&self) -> CheckpointDigest {
        self.from
    }

    /// The checkpoint it moves to.
    pub const fn target(&self) -> CheckpointDigest {
        self.to
    }
}

fn open_role<B: Body>(
    receipt: &Receipt,
    hop: Hop,
    holds: impl Fn(RoleKey) -> bool,
    now_micros: u64,
) -> Result<Opened<B>, Refusal> {
    let Some(key) = named_issuer(receipt).filter(|key| holds(*key)) else {
        return Err(Refusal::UntrustedSigner { hop });
    };
    open_under(receipt, hop, key, now_micros)
}

fn open_under<B: Body>(
    receipt: &Receipt,
    hop: Hop,
    key: RoleKey,
    now_micros: u64,
) -> Result<Opened<B>, Refusal> {
    let opened = open::<B>(receipt, key).map_err(|error| Refusal::BadReceipt { hop, error })?;
    if opened.issued_at_micros() > now_micros {
        return Err(Refusal::IssuedInFuture { hop });
    }
    Ok(opened)
}

fn inconsistent(hop: Hop, field: &str) -> Refusal {
    Refusal::Inconsistent {
        hop,
        field: field.to_owned(),
    }
}

/// What a chain that walked says was done: the digests and results a verifier
/// needs in order to replay the patch and recompute the scores.
///
/// Minted only by [`chain_facts`], from receipts that verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainFacts {
    base: CheckpointDigest,
    candidate: CheckpointDigest,
    program: ProgramDigest,
    transcript: ContentDigest,
    results: EvalResults,
}

impl ChainFacts {
    /// The checkpoint the program was applied to.
    pub const fn base(&self) -> CheckpointDigest {
        self.base
    }

    /// The checkpoint that resulted.
    pub const fn candidate(&self) -> CheckpointDigest {
        self.candidate
    }

    /// The program.
    pub const fn program(&self) -> ProgramDigest {
        self.program
    }

    /// The per-item outcomes the results were computed from.
    pub const fn transcript(&self) -> ContentDigest {
        self.transcript
    }

    /// The results the evaluator signed.
    pub const fn results(&self) -> &EvalResults {
        &self.results
    }
}

/// Walks `chain` against `policy` and `pointer` as of `now_micros`.
///
/// # Errors
///
/// The first [`Refusal`] met, in hop order.
pub fn verify_chain(
    chain: &ReleaseChain,
    policy: &ReleasePolicy,
    pointer: &PointerState,
    now_micros: u64,
) -> Result<PointerMove, Refusal> {
    walk(chain, policy, pointer, now_micros).map(|(granted, _)| granted)
}

/// Walks `chain` exactly as [`verify_chain`] does and returns what it says
/// was done. For a verifier replaying a record; it grants nothing.
///
/// # Errors
///
/// The first [`Refusal`] met, in hop order.
pub fn chain_facts(
    chain: &ReleaseChain,
    policy: &ReleasePolicy,
    pointer: &PointerState,
    now_micros: u64,
) -> Result<ChainFacts, Refusal> {
    walk(chain, policy, pointer, now_micros).map(|(_, facts)| facts)
}

/// The candidate a chain's apply receipt names, read without verifying
/// anything. It is a hint for looking something up before the walk — whether
/// the store holds the files, say — and is never evidence.
#[must_use]
pub fn claimed_candidate(chain: &ReleaseChain) -> Option<CheckpointDigest> {
    chain.apply.projections.iter().find_map(|projection| {
        let nucleus_receipt::Projection::Ci(value) = projection else {
            return None;
        };
        value
            .get("body")?
            .get("outcome")?
            .get("output")?
            .as_str()?
            .parse()
            .ok()
    })
}

pub(crate) fn walk(
    chain: &ReleaseChain,
    policy: &ReleasePolicy,
    pointer: &PointerState,
    now_micros: u64,
) -> Result<(PointerMove, ChainFacts), Refusal> {
    let ReleaseChain {
        grant,
        manifest,
        apply,
        eval,
        approval,
    } = chain;

    // Hop 1: a deployer granted authority to propose against the current base.
    let grant =
        open_role::<ProposalGrant>(grant, Hop::Grant, |key| policy.is_deployer(key), now_micros)?;
    let g = grant.body();
    if g.policy != policy.digest() {
        return Err(Refusal::PolicyMismatch { hop: Hop::Grant });
    }
    if g.base != pointer.current {
        return Err(Refusal::BaseNotCurrent {
            claimed: g.base,
            current: pointer.current,
        });
    }
    match (&g.lineage, &pointer.head) {
        (Lineage::First, Head::Genesis) => {}
        (Lineage::After { release }, Head::Release { receipt }) if release == receipt => {}
        (
            Lineage::First | Lineage::After { release: _ },
            Head::Genesis | Head::Release { receipt: _ },
        ) => {
            return Err(Refusal::LineageMismatch);
        }
    }
    if now_micros > g.not_after_micros {
        return Err(Refusal::GrantExpired);
    }
    if policy.holds_a_role(g.editor) {
        return Err(Refusal::EditorHoldsRole);
    }

    // Hop 2: the editor the grant names proposed a patch within the policy.
    let manifest = open_under::<PatchManifest>(manifest, Hop::Manifest, g.editor, now_micros)?;
    let m = manifest.body();
    if m.grant != grant.hash() {
        return Err(Refusal::BrokenLink { hop: Hop::Manifest });
    }
    if m.base != g.base {
        return Err(inconsistent(Hop::Manifest, "base"));
    }
    let not_permitted: BTreeSet<String> = m
        .declared
        .iter()
        .filter(|tensor| !policy.permitted().contains(tensor))
        .map(str::to_owned)
        .collect();
    if !not_permitted.is_empty() {
        return Err(Refusal::UnauthorizedTensorWrite {
            tensors: not_permitted,
        });
    }

    // Hop 3: a runner applied it and measured what it wrote.
    let apply =
        open_role::<ApplyReceipt>(apply, Hop::Apply, |key| policy.is_runner(key), now_micros)?;
    let a = apply.body();
    if a.manifest != manifest.hash() {
        return Err(Refusal::BrokenLink { hop: Hop::Apply });
    }
    if a.base != m.base {
        return Err(inconsistent(Hop::Apply, "base"));
    }
    if a.program != m.program {
        return Err(inconsistent(Hop::Apply, "program"));
    }
    if a.run == 0 || a.run > g.budget.max_runs {
        return Err(Refusal::BudgetExceeded {
            what: "runs".to_owned(),
        });
    }
    let candidate = match &a.outcome {
        ApplyOutcome::Applied { output, writes } => {
            // The runner says the writes were within the declaration. The
            // gate reads the writes and checks, against the declaration and
            // against the policy, rather than taking the label.
            let outside: BTreeSet<String> = writes
                .iter()
                .filter(|w| !(m.declared.contains(&w.name) && policy.permitted().contains(&w.name)))
                .map(|w| w.name.clone())
                .collect();
            if !outside.is_empty() {
                return Err(Refusal::UnauthorizedTensorWrite { tensors: outside });
            }
            if *output != m.expected_output {
                return Err(Refusal::OutputMismatch {
                    expected: m.expected_output,
                    actual: *output,
                });
            }
            *output
        }
        ApplyOutcome::WriteSetViolation {
            undeclared,
            writes: _,
        } => {
            return Err(Refusal::UnauthorizedTensorWrite {
                tensors: undeclared.iter().cloned().collect(),
            });
        }
        ApplyOutcome::OutputMismatch { expected, actual } => {
            return Err(Refusal::OutputMismatch {
                expected: *expected,
                actual: *actual,
            });
        }
        ApplyOutcome::CouldNotApply { reason } => {
            return Err(Refusal::NotApplied {
                reason: reason.clone(),
            });
        }
    };

    // Hop 4: an evaluator measured that candidate, with the policy's suite.
    let eval =
        open_role::<EvalReceipt>(eval, Hop::Eval, |key| policy.is_evaluator(key), now_micros)?;
    let e = eval.body();
    if e.candidate != candidate {
        return Err(Refusal::EvalForDifferentCandidate {
            evaluated: e.candidate,
            applied: candidate,
        });
    }
    if e.apply != apply.hash() {
        return Err(Refusal::BrokenLink { hop: Hop::Eval });
    }
    if e.base != g.base {
        return Err(inconsistent(Hop::Eval, "base"));
    }
    if e.suite != *policy.suite() || e.decoding != *policy.decoding() {
        return Err(Refusal::EvalConfigMismatch);
    }
    if e.accelerator_seconds > g.budget.max_accelerator_seconds {
        return Err(Refusal::BudgetExceeded {
            what: "accelerator seconds".to_owned(),
        });
    }
    check_thresholds(&e.results, policy.thresholds())
        .map_err(|failure| Refusal::ThresholdNotMet { failure })?;

    // Hop 5: a deployer, who is not the editor, approved this candidate for
    // this move.
    let Some(approval) = approval else {
        return Err(Refusal::MissingApproval);
    };
    if named_issuer(approval) == Some(g.editor) {
        return Err(Refusal::ApproverNotDistinct);
    }
    let approval = open_role::<Approval>(
        approval,
        Hop::Approval,
        |key| policy.is_deployer(key),
        now_micros,
    )?;
    let p = approval.body();
    if p.eval != eval.hash() {
        return Err(Refusal::BrokenLink { hop: Hop::Approval });
    }
    if p.candidate != candidate {
        return Err(Refusal::ForDifferentCheckpoint { hop: Hop::Approval });
    }
    if p.policy != policy.digest() {
        return Err(Refusal::PolicyMismatch { hop: Hop::Approval });
    }
    if p.generation != pointer.generation {
        return Err(Refusal::StaleGeneration {
            hop: Hop::Approval,
            approved: p.generation,
            current: pointer.generation,
        });
    }
    if now_micros > p.not_after_micros {
        return Err(Refusal::Expired { hop: Hop::Approval });
    }

    let granted = PointerMove {
        from: pointer.current,
        to: candidate,
        generation: pointer.generation,
        not_after: g.not_after_micros.min(p.not_after_micros),
        transition: Transition::Promotion {
            grant: grant.hash(),
            manifest: manifest.hash(),
            apply: apply.hash(),
            eval: eval.hash(),
            approval: approval.hash(),
        },
    };
    let facts = ChainFacts {
        base: g.base,
        candidate,
        program: m.program,
        transcript: e.transcript,
        results: e.results.clone(),
    };
    Ok((granted, facts))
}

/// Checks a rollback order against `policy` and `pointer` as of `now_micros`.
///
/// # Errors
///
/// The [`Refusal`] that applies.
pub fn verify_rollback(
    order: &Receipt,
    policy: &ReleasePolicy,
    pointer: &PointerState,
    now_micros: u64,
) -> Result<PointerMove, Refusal> {
    let hop = Hop::RollbackOrder;
    let order = open_role::<RollbackOrder>(order, hop, |key| policy.is_deployer(key), now_micros)?;
    let o = order.body();
    if o.policy != policy.digest() {
        return Err(Refusal::PolicyMismatch { hop });
    }
    if o.generation != pointer.generation {
        return Err(Refusal::StaleGeneration {
            hop,
            approved: o.generation,
            current: pointer.generation,
        });
    }
    let retained = match pointer.previous {
        Previous::Nothing => return Err(Refusal::NothingToRollBackTo),
        Previous::Checkpoint { digest } => digest,
    };
    if o.to != retained {
        return Err(Refusal::ForDifferentCheckpoint { hop });
    }
    if now_micros > o.not_after_micros {
        return Err(Refusal::Expired { hop });
    }
    Ok(PointerMove {
        from: pointer.current,
        to: retained,
        generation: pointer.generation,
        not_after: o.not_after_micros,
        transition: Transition::Rollback {
            order: order.hash(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::seal;
    use crate::testkit::{Draft, NOW, World, digest_of, key, outcomes};

    fn start(world: &World) -> PointerState {
        PointerState::genesis(world.genesis())
    }

    fn honest(world: &World) -> Draft {
        Draft::honest(
            world,
            &start(world),
            &world.genesis_file,
            &["layer.0.bias"],
            &["layer.0.bias"],
        )
    }

    fn walk(world: &World, chain: &ReleaseChain) -> Result<PointerMove, Refusal> {
        verify_chain(chain, &world.policy, &start(world), NOW)
    }

    #[test]
    fn an_honest_chain_yields_one_move_to_the_candidate() {
        let world = World::new();
        let draft = honest(&world);
        let granted = walk(&world, &draft.sign()).unwrap();
        assert_eq!(granted.source(), world.genesis());
        assert_eq!(granted.target(), digest_of(&draft.output_file));
        assert_ne!(granted.target(), world.genesis());
        assert_eq!(granted.generation, 0);
    }

    #[test]
    fn a_higher_scoring_candidate_without_approval_is_refused() {
        let world = World::new();
        let mut transcript = outcomes("math", 200, 100, 190, 0);
        transcript.extend(outcomes("reading", 100, 80, 90, 0));
        let mut draft = honest(&world).with_transcript(&transcript);
        draft.approval = None;
        assert_eq!(
            walk(&world, &draft.sign()).unwrap_err(),
            Refusal::MissingApproval
        );
    }

    #[test]
    fn an_evaluation_of_a_different_checkpoint_is_refused() {
        let world = World::new();
        // The evaluator measured files that are not the runner's output.
        let mut draft = honest(&world);
        draft.eval.candidate = world.genesis();
        assert!(matches!(
            walk(&world, &draft.sign()).unwrap_err(),
            Refusal::EvalForDifferentCandidate { .. }
        ));

        // A genuine evaluation receipt, lifted from another candidate's chain.
        let other = Draft::honest(
            &world,
            &start(&world),
            &world.genesis_file,
            &["layer.1.bias"],
            &["layer.1.bias"],
        )
        .sign();
        let mut chain = honest(&world).sign();
        chain.eval = other.eval;
        assert!(matches!(
            walk(&world, &chain).unwrap_err(),
            Refusal::EvalForDifferentCandidate { .. }
        ));
    }

    fn tensors(refusal: Refusal) -> Vec<String> {
        match refusal {
            Refusal::UnauthorizedTensorWrite { tensors } => tensors.into_iter().collect(),
            other => panic!("expected an unauthorized write, got {other:?}"),
        }
    }

    #[test]
    fn a_patch_declaring_a_tensor_the_policy_does_not_permit_is_refused() {
        let world = World::new();
        let draft = Draft::honest(
            &world,
            &start(&world),
            &world.genesis_file,
            &["layer.0.bias", "embed.weight"],
            &["layer.0.bias", "embed.weight"],
        );
        assert_eq!(
            tensors(walk(&world, &draft.sign()).unwrap_err()),
            ["embed.weight"]
        );
    }

    #[test]
    fn a_declaration_wider_than_the_policy_is_refused_even_if_nothing_is_written_there() {
        let world = World::new();
        // The program stays inside the policy; the declaration does not. The
        // measured writes are all permitted, so only the declaration check
        // can refuse this.
        let draft = Draft::honest(
            &world,
            &start(&world),
            &world.genesis_file,
            &["layer.0.bias"],
            &["layer.0.bias", "embed.weight"],
        );
        assert!(matches!(draft.apply.outcome, ApplyOutcome::Applied { .. }));
        assert_eq!(
            tensors(walk(&world, &draft.sign()).unwrap_err()),
            ["embed.weight"]
        );
    }

    #[test]
    fn a_patch_writing_a_tensor_it_did_not_declare_is_refused() {
        let world = World::new();
        // The program writes two tensors; the manifest declares one. The
        // honest runner measures the second write and says so.
        let draft = Draft::honest(
            &world,
            &start(&world),
            &world.genesis_file,
            &["layer.0.bias", "layer.1.bias"],
            &["layer.0.bias"],
        );
        assert!(matches!(
            draft.apply.outcome,
            ApplyOutcome::WriteSetViolation { .. }
        ));
        assert_eq!(
            tensors(walk(&world, &draft.sign()).unwrap_err()),
            ["layer.1.bias"]
        );
    }

    #[test]
    fn a_runner_that_calls_an_undeclared_write_applied_is_not_believed() {
        let world = World::new();
        let mut draft = Draft::honest(
            &world,
            &start(&world),
            &world.genesis_file,
            &["layer.0.bias", "layer.1.bias"],
            &["layer.0.bias"],
        );
        let ApplyOutcome::WriteSetViolation { writes, .. } = draft.apply.outcome.clone() else {
            panic!("the honest runner reports the violation");
        };
        draft.apply.outcome = ApplyOutcome::Applied {
            output: draft.manifest.expected_output,
            writes,
        };
        assert_eq!(
            tensors(walk(&world, &draft.sign()).unwrap_err()),
            ["layer.1.bias"]
        );
    }

    #[test]
    fn an_approval_signed_by_the_editor_is_refused() {
        let world = World::new();
        let mut draft = honest(&world);
        draft.signers.approval = world.editor.clone();
        assert_eq!(
            walk(&world, &draft.sign()).unwrap_err(),
            Refusal::ApproverNotDistinct
        );
    }

    #[test]
    fn an_approval_signed_by_a_key_with_no_role_is_refused() {
        let world = World::new();
        let mut draft = honest(&world);
        draft.signers.approval = key(77);
        assert_eq!(
            walk(&world, &draft.sign()).unwrap_err(),
            Refusal::UntrustedSigner { hop: Hop::Approval }
        );
    }

    #[test]
    fn each_role_is_checked_at_its_own_hop() {
        let world = World::new();
        for (hop, replace) in [(Hop::Grant, 0u8), (Hop::Apply, 1), (Hop::Eval, 2)] {
            let mut draft = honest(&world);
            // The evaluator's key at the grant and apply hops, the runner's
            // at the evaluation hop: a real role key, in the wrong place.
            match replace {
                0 => draft.signers.grant = world.evaluator.clone(),
                1 => draft.signers.apply = world.evaluator.clone(),
                _ => draft.signers.eval = world.runner.clone(),
            }
            assert_eq!(
                walk(&world, &draft.sign()).unwrap_err(),
                Refusal::UntrustedSigner { hop },
            );
        }
    }

    #[test]
    fn a_manifest_not_signed_by_the_granted_editor_is_refused() {
        let world = World::new();
        let mut draft = honest(&world);
        draft.signers.manifest = key(77);
        assert!(matches!(
            walk(&world, &draft.sign()).unwrap_err(),
            Refusal::BadReceipt {
                hop: Hop::Manifest,
                ..
            }
        ));
    }

    #[test]
    fn a_grant_naming_a_role_holder_as_editor_is_refused() {
        let world = World::new();
        let mut draft = honest(&world);
        draft.grant.editor = RoleKey::of(&world.deployer);
        draft.signers.manifest = world.deployer.clone();
        assert_eq!(
            walk(&world, &draft.sign()).unwrap_err(),
            Refusal::EditorHoldsRole
        );
    }

    #[test]
    fn an_expired_grant_or_approval_is_refused() {
        let world = World::new();
        let mut draft = honest(&world);
        draft.grant.not_after_micros = NOW - 1;
        assert_eq!(
            walk(&world, &draft.sign()).unwrap_err(),
            Refusal::GrantExpired
        );

        let mut draft = honest(&world);
        draft.approval.as_mut().unwrap().not_after_micros = NOW - 1;
        assert_eq!(
            walk(&world, &draft.sign()).unwrap_err(),
            Refusal::Expired { hop: Hop::Approval }
        );
    }

    #[test]
    fn a_receipt_dated_after_the_decision_is_refused() {
        let world = World::new();
        let chain = honest(&world).sign();
        // Decide before the approval was signed.
        assert_eq!(
            verify_chain(&chain, &world.policy, &start(&world), NOW - 6).unwrap_err(),
            Refusal::IssuedInFuture { hop: Hop::Approval }
        );
    }

    #[test]
    fn a_spent_budget_is_refused() {
        let world = World::new();
        let mut draft = honest(&world);
        draft.apply.run = 2;
        assert!(matches!(
            walk(&world, &draft.sign()).unwrap_err(),
            Refusal::BudgetExceeded { .. }
        ));

        let mut draft = honest(&world);
        draft.eval.accelerator_seconds = 3601;
        assert!(matches!(
            walk(&world, &draft.sign()).unwrap_err(),
            Refusal::BudgetExceeded { .. }
        ));
    }

    #[test]
    fn an_evaluation_below_a_threshold_is_refused() {
        let world = World::new();
        // A large gain on the target task and a loss on the unrelated one.
        let mut transcript = outcomes("math", 200, 100, 190, 0);
        transcript.extend(outcomes("reading", 100, 80, 70, 0));
        let draft = honest(&world).with_transcript(&transcript);
        assert!(matches!(
            walk(&world, &draft.sign()).unwrap_err(),
            Refusal::ThresholdNotMet {
                failure: ThresholdFailure::UnrelatedRegression { .. }
            }
        ));
    }

    #[test]
    fn an_evaluation_with_other_settings_is_refused() {
        let world = World::new();
        let mut draft = honest(&world);
        draft.eval.decoding.max_tokens = 4096;
        assert_eq!(
            walk(&world, &draft.sign()).unwrap_err(),
            Refusal::EvalConfigMismatch
        );
        let mut draft = honest(&world);
        draft.eval.suite.version = "suite-2".to_owned();
        assert_eq!(
            walk(&world, &draft.sign()).unwrap_err(),
            Refusal::EvalConfigMismatch
        );
    }

    #[test]
    fn a_grant_or_approval_under_another_policy_is_refused() {
        let world = World::new();
        let other = crate::keys::PolicyDigest::from_bytes([0xee; 32]);
        let mut draft = honest(&world);
        draft.grant.policy = other;
        assert_eq!(
            walk(&world, &draft.sign()).unwrap_err(),
            Refusal::PolicyMismatch { hop: Hop::Grant }
        );
        let mut draft = honest(&world);
        draft.approval.as_mut().unwrap().policy = other;
        assert_eq!(
            walk(&world, &draft.sign()).unwrap_err(),
            Refusal::PolicyMismatch { hop: Hop::Approval }
        );
    }

    #[test]
    fn an_approval_for_another_generation_is_refused() {
        let world = World::new();
        let mut draft = honest(&world);
        draft.approval.as_mut().unwrap().generation = 1;
        assert_eq!(
            walk(&world, &draft.sign()).unwrap_err(),
            Refusal::StaleGeneration {
                hop: Hop::Approval,
                approved: 1,
                current: 0
            }
        );
    }

    #[test]
    fn a_receipt_lifted_from_another_chain_breaks_the_link() {
        let world = World::new();
        let chain = honest(&world).sign();
        // The same proposal under a second, different grant.
        let mut second = honest(&world);
        second.grant.not_after_micros += 1;
        let second = second.sign();

        let mut swapped = chain.clone();
        swapped.grant = second.grant.clone();
        assert_eq!(
            walk(&world, &swapped).unwrap_err(),
            Refusal::BrokenLink { hop: Hop::Manifest }
        );
        let mut swapped = chain.clone();
        swapped.apply = second.apply.clone();
        assert_eq!(
            walk(&world, &swapped).unwrap_err(),
            Refusal::BrokenLink { hop: Hop::Apply }
        );
        let mut swapped = chain;
        swapped.approval = second.approval;
        assert_eq!(
            walk(&world, &swapped).unwrap_err(),
            Refusal::BrokenLink { hop: Hop::Approval }
        );
    }

    #[test]
    fn a_receipt_changed_after_signing_is_refused() {
        let world = World::new();
        let mut chain = honest(&world).sign();
        chain.eval.session.issued_at_micros += 1;
        assert!(matches!(
            walk(&world, &chain).unwrap_err(),
            Refusal::BadReceipt { hop: Hop::Eval, .. }
        ));
    }

    #[test]
    fn a_grant_for_a_checkpoint_that_is_not_being_served_is_refused() {
        let world = World::new();
        let chain = honest(&world).sign();
        let mut elsewhere = start(&world);
        elsewhere.current = digest_of(&honest(&world).output_file);
        assert!(matches!(
            verify_chain(&chain, &world.policy, &elsewhere, NOW).unwrap_err(),
            Refusal::BaseNotCurrent { .. }
        ));
    }

    #[test]
    fn a_rollback_order_needs_a_deployer_and_something_to_return_to() {
        let world = World::new();
        let order = |signer: &ed25519_dalek::SigningKey, to, generation| {
            seal(
                &RollbackOrder {
                    generation,
                    to,
                    policy: world.policy.digest(),
                    not_after_micros: NOW + 10,
                },
                signer,
                "spiffe://test/deployer",
                NOW - 1,
            )
            .unwrap()
        };
        let candidate = digest_of(&honest(&world).output_file);
        let moved = PointerState {
            current: candidate,
            previous: Previous::Checkpoint {
                digest: world.genesis(),
            },
            generation: 1,
            head: Head::Release {
                receipt: ReceiptHash::from_bytes([3; 32]),
            },
        };
        let check = |order: &Receipt, pointer: &PointerState| {
            verify_rollback(order, &world.policy, pointer, NOW)
        };

        let granted = check(&order(&world.deployer, world.genesis(), 1), &moved).unwrap();
        assert_eq!(
            (granted.source(), granted.target()),
            (candidate, world.genesis())
        );

        assert_eq!(
            check(&order(&world.editor, world.genesis(), 1), &moved).unwrap_err(),
            Refusal::UntrustedSigner {
                hop: Hop::RollbackOrder
            }
        );
        assert_eq!(
            check(&order(&world.deployer, candidate, 1), &moved).unwrap_err(),
            Refusal::ForDifferentCheckpoint {
                hop: Hop::RollbackOrder
            }
        );
        assert!(matches!(
            check(&order(&world.deployer, world.genesis(), 0), &moved).unwrap_err(),
            Refusal::StaleGeneration { .. }
        ));
        assert_eq!(
            check(&order(&world.deployer, world.genesis(), 0), &start(&world)).unwrap_err(),
            Refusal::NothingToRollBackTo
        );
    }
}
