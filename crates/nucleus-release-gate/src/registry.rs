//! The registry: the serving pointer on disk, the log of every move, and the
//! two ways to move it.
//!
//! # State
//!
//! A directory holding:
//!
//! - `pointer.json` — the current digest, the previous digest, the
//!   generation, and the receipt that put the current digest in place;
//! - `releases.jsonl` — one record per move: the registry-signed release
//!   receipt and the evidence it was made on;
//! - `refusals.jsonl` — one registry-signed notice per refused attempt;
//! - `lock` — held for the whole of a decision.
//!
//! # Order of writes, and what a crash leaves
//!
//! A move appends its record to the log, synced, and then replaces the
//! pointer file by rename. A crash between the two leaves a log one record
//! ahead of the pointer. [`Registry::open`] finds that, checks the record is
//! the registry's own and follows from the pointer, and completes the move.
//! The pointer is never ahead of the log, so there is no served checkpoint
//! without a record of why.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use nucleus_receipt::Receipt;
use nucleus_weight_patch::CheckpointDigest;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::body::{OpenError, Opened, RefusalNotice, ReleaseReceipt, SealError, open, seal};
use crate::chain::{
    ChainFacts, Head, PointerMove, PointerState, Previous, Refusal, ReleaseChain, verify_chain,
    verify_rollback, walk,
};
use crate::keys::RoleKey;
use crate::policy::ReleasePolicy;

const POINTER_FILE: &str = "pointer.json";
const POINTER_TMP: &str = "pointer.json.tmp";
const RELEASES_FILE: &str = "releases.jsonl";
const REFUSALS_FILE: &str = "refusals.jsonl";
const LOCK_FILE: &str = "lock";

/// The evidence a move was made on.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "evidence", rename_all = "snake_case", deny_unknown_fields)]
pub enum Evidence {
    /// A promotion's chain.
    Promotion {
        /// The chain.
        chain: Box<ReleaseChain>,
    },
    /// A rollback's order.
    Rollback {
        /// The order.
        order: Receipt,
    },
}

/// One line of the release log.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseRecord {
    /// The registry's signed account of the move.
    pub release: Receipt,
    /// What it was made on.
    pub evidence: Evidence,
}

/// Why the registry could not decide. Never a refusal, and never a pass.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// The directory could not be read or written.
    #[error("registry storage: {0}")]
    Io(#[from] io::Error),
    /// A file does not hold what the registry wrote.
    #[error("registry state is not what the registry wrote: {detail}")]
    Corrupt {
        /// What is wrong.
        detail: String,
    },
    /// A registry already exists in the directory.
    #[error("a registry already exists in this directory")]
    AlreadyExists,
    /// A receipt could not be signed.
    #[error(transparent)]
    Seal(#[from] SealError),
    /// A move's right no longer matches the pointer it was minted against.
    #[error("the pointer changed between the decision and the move")]
    StaleMove,
    /// The generation counter is exhausted.
    #[error("the generation counter is exhausted")]
    GenerationExhausted,
}

impl From<serde_json::Error> for RegistryError {
    fn from(e: serde_json::Error) -> Self {
        Self::Corrupt {
            detail: e.to_string(),
        }
    }
}

/// The answer to a request to move the pointer.
#[derive(Debug)]
pub enum MoveVerdict {
    /// The pointer moved.
    Moved {
        /// The registry's signed account of the move.
        release: Receipt,
        /// The pointer after it.
        pointer: PointerState,
    },
    /// The pointer did not move, for this reason.
    Refused {
        /// The reason.
        refusal: Refusal,
        /// The pointer, unchanged.
        pointer: PointerState,
    },
    /// The registry could not look. The pointer did not move.
    CouldNotLook(RegistryError),
}

/// The serving pointer and its log.
#[derive(Debug)]
pub struct Registry {
    dir: PathBuf,
    policy: ReleasePolicy,
    signer: SigningKey,
    session_id: String,
}

impl Registry {
    /// Creates a registry in `dir`, serving `genesis`.
    ///
    /// # Errors
    ///
    /// [`RegistryError::AlreadyExists`] if `dir` already holds a pointer;
    /// [`RegistryError::Io`] if it cannot be written.
    pub fn create(
        dir: &Path,
        genesis: CheckpointDigest,
        policy: ReleasePolicy,
        signer: SigningKey,
        session_id: &str,
    ) -> Result<Self, RegistryError> {
        fs::create_dir_all(dir)?;
        let registry = Self {
            dir: dir.to_owned(),
            policy,
            signer,
            session_id: session_id.to_owned(),
        };
        let _lock = registry.lock()?;
        if registry.path(POINTER_FILE).try_exists()? {
            return Err(RegistryError::AlreadyExists);
        }
        registry.write_pointer(&PointerState::genesis(genesis))?;
        Ok(registry)
    }

    /// Opens the registry in `dir`, completing a move a crash interrupted.
    ///
    /// # Errors
    ///
    /// [`RegistryError::Io`] if the state cannot be read;
    /// [`RegistryError::Corrupt`] if the log and the pointer disagree in a way
    /// no crash of this code produces.
    pub fn open(
        dir: &Path,
        policy: ReleasePolicy,
        signer: SigningKey,
        session_id: &str,
    ) -> Result<Self, RegistryError> {
        let registry = Self {
            dir: dir.to_owned(),
            policy,
            signer,
            session_id: session_id.to_owned(),
        };
        let _lock = registry.lock()?;
        let pointer = registry.read_pointer()?;
        if let Some(last) = registry.records()?.last() {
            let opened = registry.own(&last.release)?;
            let left = left_by(&opened);
            if left == pointer {
                // The last move completed.
            } else if pointer.generation.checked_add(1) == Some(left.generation)
                && opened.body().previous == pointer.current
            {
                // The record was written and the pointer was not: finish.
                registry.write_pointer(&left)?;
            } else {
                return Err(RegistryError::Corrupt {
                    detail: "the last release does not follow from the pointer".to_owned(),
                });
            }
        } else if pointer.generation != 0 {
            return Err(RegistryError::Corrupt {
                detail: "the pointer has moved and the release log is empty".to_owned(),
            });
        }
        Ok(registry)
    }

    /// The policy the registry decides under.
    pub const fn policy(&self) -> &ReleasePolicy {
        &self.policy
    }

    /// The key the registry signs with.
    pub fn key(&self) -> RoleKey {
        RoleKey::of(&self.signer)
    }

    /// The pointer as stored.
    ///
    /// # Errors
    ///
    /// [`RegistryError`] if it cannot be read or is not what was written.
    pub fn pointer(&self) -> Result<PointerState, RegistryError> {
        self.read_pointer()
    }

    /// Every record in the release log, oldest first.
    ///
    /// # Errors
    ///
    /// [`RegistryError`] if the log cannot be read or a line does not parse.
    pub fn records(&self) -> Result<Vec<ReleaseRecord>, RegistryError> {
        read_lines(&self.path(RELEASES_FILE))
    }

    /// Every refusal notice, oldest first.
    ///
    /// # Errors
    ///
    /// [`RegistryError`] if the log cannot be read or a line does not parse.
    pub fn refusals(&self) -> Result<Vec<Receipt>, RegistryError> {
        read_lines(&self.path(REFUSALS_FILE))
    }

    /// Promotes the candidate `chain` is evidence for, if the chain holds.
    pub fn promote(&self, chain: &ReleaseChain, now_micros: u64) -> MoveVerdict {
        self.decide(
            now_micros,
            |pointer| verify_chain(chain, &self.policy, pointer, now_micros),
            || Evidence::Promotion {
                chain: Box::new(chain.clone()),
            },
        )
    }

    /// Returns to the retained previous checkpoint, if `order` holds.
    pub fn rollback(&self, order: &Receipt, now_micros: u64) -> MoveVerdict {
        self.decide(
            now_micros,
            |pointer| verify_rollback(order, &self.policy, pointer, now_micros),
            || Evidence::Rollback {
                order: order.clone(),
            },
        )
    }

    fn decide(
        &self,
        now_micros: u64,
        verify: impl FnOnce(&PointerState) -> Result<PointerMove, Refusal>,
        evidence: impl FnOnce() -> Evidence,
    ) -> MoveVerdict {
        let _lock = match self.lock() {
            Ok(lock) => lock,
            Err(e) => return MoveVerdict::CouldNotLook(e),
        };
        let pointer = match self.read_pointer() {
            Ok(pointer) => pointer,
            Err(e) => return MoveVerdict::CouldNotLook(e),
        };
        match verify(&pointer) {
            Ok(granted) => match self.advance(granted, &pointer, now_micros, evidence()) {
                Ok((release, pointer)) => MoveVerdict::Moved { release, pointer },
                Err(e) => MoveVerdict::CouldNotLook(e),
            },
            Err(refusal) => match self.note_refusal(&pointer, &refusal, now_micros) {
                Ok(()) => MoveVerdict::Refused { refusal, pointer },
                // The attempt was refused and could not be recorded. The
                // pointer did not move either way; the caller is told the
                // record is missing rather than handed a clean refusal.
                Err(e) => MoveVerdict::CouldNotLook(e),
            },
        }
    }

    /// Spends `granted`: logs the move, then moves the pointer.
    fn advance(
        &self,
        granted: PointerMove,
        pointer: &PointerState,
        now_micros: u64,
        evidence: Evidence,
    ) -> Result<(Receipt, PointerState), RegistryError> {
        let PointerMove {
            from,
            to,
            generation,
            not_after,
            transition,
        } = granted;
        if generation != pointer.generation || from != pointer.current || now_micros > not_after {
            return Err(RegistryError::StaleMove);
        }
        let Some(next_generation) = generation.checked_add(1) else {
            return Err(RegistryError::GenerationExhausted);
        };
        let body = ReleaseReceipt {
            previous: from,
            current: to,
            generation: next_generation,
            transition,
        };
        let release = seal(&body, &self.signer, &self.session_id, now_micros)?;
        let opened = self.own(&release)?;
        let record = ReleaseRecord {
            release: release.clone(),
            evidence,
        };
        append_record(&self.path(RELEASES_FILE), &serde_json::to_string(&record)?)?;
        let next = left_by(&opened);
        self.write_pointer(&next)?;
        Ok((release, next))
    }

    fn note_refusal(
        &self,
        pointer: &PointerState,
        refusal: &Refusal,
        now_micros: u64,
    ) -> Result<(), RegistryError> {
        let notice = RefusalNotice {
            current: pointer.current,
            generation: pointer.generation,
            refusal: refusal.clone(),
        };
        let receipt = seal(&notice, &self.signer, &self.session_id, now_micros)?;
        append_record(&self.path(REFUSALS_FILE), &serde_json::to_string(&receipt)?)?;
        Ok(())
    }

    fn own(&self, release: &Receipt) -> Result<Opened<ReleaseReceipt>, RegistryError> {
        open::<ReleaseReceipt>(release, self.key()).map_err(|e: OpenError| RegistryError::Corrupt {
            detail: format!("a release in the log is not this registry's: {e}"),
        })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn lock(&self) -> Result<File, RegistryError> {
        let file = File::options()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.path(LOCK_FILE))?;
        file.lock()?;
        Ok(file)
    }

    fn read_pointer(&self) -> Result<PointerState, RegistryError> {
        let bytes = fs::read(self.path(POINTER_FILE))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    fn write_pointer(&self, pointer: &PointerState) -> Result<(), RegistryError> {
        let tmp = self.path(POINTER_TMP);
        let mut file = File::create(&tmp)?;
        file.write_all(&serde_json::to_vec(pointer)?)?;
        file.sync_all()?;
        fs::rename(&tmp, self.path(POINTER_FILE))?;
        File::open(&self.dir)?.sync_all()?;
        Ok(())
    }
}

/// The pointer a release leaves behind. A release receipt carries everything
/// the pointer holds, so the pointer is a function of the last release.
fn left_by(release: &Opened<ReleaseReceipt>) -> PointerState {
    PointerState {
        current: release.body().current,
        previous: Previous::Checkpoint {
            digest: release.body().previous,
        },
        generation: release.body().generation,
        head: Head::Release {
            receipt: release.hash(),
        },
    }
}

/// Appends one synced line, and holds the log to its own proof that the
/// line it acknowledges is the line that was asked for.
fn append_record(path: &Path, line: &str) -> Result<(), RegistryError> {
    let durable = nucleus_jsonl::append_line_synced(path, line)?;
    if durable.proves(path, line) {
        Ok(())
    } else {
        Err(RegistryError::Corrupt {
            detail: "the log acknowledged a different record from the one written".to_owned(),
        })
    }
}

fn read_lines<T: DeserializeOwned>(path: &Path) -> Result<Vec<T>, RegistryError> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    text.lines()
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

/// Why a release log did not replay.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// A release receipt is not the registry's.
    #[error("record {index}: the release receipt is not the registry's: {error}")]
    NotTheRegistrys {
        /// The record's position in the log.
        index: usize,
        /// Why.
        error: OpenError,
    },
    /// The evidence does not justify the move, as of the move's own time.
    #[error("record {index}: the evidence does not justify the move: {refusal}")]
    Unjustified {
        /// The record's position in the log.
        index: usize,
        /// Why.
        refusal: Refusal,
    },
    /// The release receipt records a different move from the one its evidence
    /// justifies.
    #[error("record {index}: the release receipt is not the move its evidence justifies")]
    WrongMove {
        /// The record's position in the log.
        index: usize,
    },
}

/// What one record of a log did, as replayed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Replayed {
    /// A promotion, with what its chain says was done.
    Promotion(ChainFacts),
    /// A rollback.
    Rollback,
}

/// One replayed record: the pointer after it, and what it did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditStep {
    /// The pointer after the move.
    pub pointer: PointerState,
    /// What the move was.
    pub replayed: Replayed,
}

/// Replays a release log from `genesis`, one step per record.
///
/// This is the stranger's check. It takes the policy, the registry's public
/// key and the records; it reads no registry state. Each record's evidence is
/// re-walked against the pointer as it stood, at the time the registry signed
/// the move, and the signed move must be exactly the one the evidence
/// justifies.
///
/// # Errors
///
/// [`AuditError`] at the first record that does not replay.
pub fn audit_steps(
    genesis: CheckpointDigest,
    policy: &ReleasePolicy,
    registry: RoleKey,
    records: &[ReleaseRecord],
) -> Result<Vec<AuditStep>, AuditError> {
    let mut pointer = PointerState::genesis(genesis);
    let mut steps = Vec::with_capacity(records.len());
    for (index, record) in records.iter().enumerate() {
        let ReleaseRecord { release, evidence } = record;
        let opened = open::<ReleaseReceipt>(release, registry)
            .map_err(|error| AuditError::NotTheRegistrys { index, error })?;
        let at = opened.issued_at_micros();
        let unjustified = |refusal| AuditError::Unjustified { index, refusal };
        let (justified, replayed) = match evidence {
            Evidence::Promotion { chain } => {
                let (granted, facts) = walk(chain, policy, &pointer, at).map_err(unjustified)?;
                (granted, Replayed::Promotion(facts))
            }
            Evidence::Rollback { order } => (
                verify_rollback(order, policy, &pointer, at).map_err(unjustified)?,
                Replayed::Rollback,
            ),
        };
        let PointerMove {
            from,
            to,
            generation,
            not_after: _,
            transition,
        } = justified;
        let expected = generation
            .checked_add(1)
            .map(|next_generation| ReleaseReceipt {
                previous: from,
                current: to,
                generation: next_generation,
                transition,
            });
        if expected.as_ref() != Some(opened.body()) {
            return Err(AuditError::WrongMove { index });
        }
        pointer = left_by(&opened);
        steps.push(AuditStep { pointer, replayed });
    }
    Ok(steps)
}

/// Replays a release log from `genesis` and returns the pointer it leads to.
///
/// # Errors
///
/// [`AuditError`] at the first record that does not replay.
pub fn audit(
    genesis: CheckpointDigest,
    policy: &ReleasePolicy,
    registry: RoleKey,
    records: &[ReleaseRecord],
) -> Result<PointerState, AuditError> {
    let steps = audit_steps(genesis, policy, registry, records)?;
    Ok(steps
        .last()
        .map_or_else(|| PointerState::genesis(genesis), |step| step.pointer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::{Lineage, RollbackOrder, Transition};
    use crate::chain::Hop;
    use crate::testkit::{Draft, NOW, World, digest_of};

    fn registry(world: &World, dir: &Path) -> Registry {
        Registry::create(
            dir,
            world.genesis(),
            world.policy.clone(),
            world.registry.clone(),
            "spiffe://test/registry",
        )
        .unwrap()
    }

    fn reopen(world: &World, dir: &Path) -> Result<Registry, RegistryError> {
        Registry::open(
            dir,
            world.policy.clone(),
            world.registry.clone(),
            "spiffe://test/registry",
        )
    }

    fn first_patch(world: &World, registry: &Registry) -> Draft {
        Draft::honest(
            world,
            &registry.pointer().unwrap(),
            &world.genesis_file,
            &["layer.0.bias"],
            &["layer.0.bias"],
        )
    }

    fn moved(verdict: MoveVerdict) -> (Receipt, PointerState) {
        match verdict {
            MoveVerdict::Moved { release, pointer } => (release, pointer),
            other => panic!("expected the pointer to move, got {other:?}"),
        }
    }

    fn refused(verdict: MoveVerdict) -> (Refusal, PointerState) {
        match verdict {
            MoveVerdict::Refused { refusal, pointer } => (refusal, pointer),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    fn order(world: &World, registry: &Registry) -> Receipt {
        let pointer = registry.pointer().unwrap();
        let Previous::Checkpoint { digest } = pointer.previous else {
            panic!("nothing retained");
        };
        seal(
            &RollbackOrder {
                generation: pointer.generation,
                to: digest,
                policy: world.policy.digest(),
                not_after_micros: NOW + 1000,
            },
            &world.deployer,
            "spiffe://test/deployer",
            NOW + 1,
        )
        .unwrap()
    }

    fn replay(world: &World, registry: &Registry) -> Result<PointerState, AuditError> {
        audit(
            world.genesis(),
            &world.policy,
            RoleKey::of(&world.registry),
            &registry.records().unwrap(),
        )
    }

    #[test]
    fn a_new_registry_serves_its_genesis() {
        let world = World::new();
        let dir = tempfile::tempdir().unwrap();
        let registry = registry(&world, dir.path());
        assert_eq!(
            registry.pointer().unwrap(),
            PointerState::genesis(world.genesis())
        );
        assert!(matches!(
            Registry::create(
                dir.path(),
                world.genesis(),
                world.policy.clone(),
                world.registry.clone(),
                "spiffe://test/registry",
            ),
            Err(RegistryError::AlreadyExists)
        ));
    }

    #[test]
    fn a_valid_chain_moves_the_pointer_and_keeps_the_previous_digest() {
        let world = World::new();
        let dir = tempfile::tempdir().unwrap();
        let registry = registry(&world, dir.path());
        let draft = first_patch(&world, &registry);

        let (release, pointer) = moved(registry.promote(&draft.sign(), NOW));

        let candidate = digest_of(&draft.output_file);
        assert_eq!(pointer.current, candidate);
        assert_eq!(
            pointer.previous,
            Previous::Checkpoint {
                digest: world.genesis()
            }
        );
        assert_eq!(pointer.generation, 1);
        assert_eq!(registry.pointer().unwrap(), pointer);

        let opened = open::<ReleaseReceipt>(&release, registry.key()).unwrap();
        assert_eq!(opened.body().previous, world.genesis());
        assert_eq!(opened.body().current, candidate);
        assert!(matches!(
            opened.body().transition,
            Transition::Promotion { .. }
        ));
        assert_eq!(
            pointer.head,
            Head::Release {
                receipt: opened.hash()
            }
        );
        assert_eq!(replay(&world, &registry).unwrap(), pointer);
    }

    #[test]
    fn a_refused_chain_leaves_the_pointer_and_a_signed_notice() {
        let world = World::new();
        let dir = tempfile::tempdir().unwrap();
        let registry = registry(&world, dir.path());
        let mut draft = first_patch(&world, &registry);
        draft.approval = None;

        let (refusal, pointer) = refused(registry.promote(&draft.sign(), NOW));

        assert_eq!(refusal, Refusal::MissingApproval);
        assert_eq!(pointer, PointerState::genesis(world.genesis()));
        assert_eq!(registry.pointer().unwrap(), pointer);
        assert!(registry.records().unwrap().is_empty());
        let notices = registry.refusals().unwrap();
        let [notice] = notices.as_slice() else {
            panic!("one refusal, one notice");
        };
        let notice = open::<RefusalNotice>(notice, registry.key()).unwrap();
        assert_eq!(notice.body().refusal, Refusal::MissingApproval);
        assert_eq!(notice.body().current, world.genesis());
        assert_eq!(notice.body().generation, 0);
    }

    #[test]
    fn a_chain_moves_the_pointer_once() {
        let world = World::new();
        let dir = tempfile::tempdir().unwrap();
        let registry = registry(&world, dir.path());
        let chain = first_patch(&world, &registry).sign();
        let (_, after_first) = moved(registry.promote(&chain, NOW));

        let (refusal, pointer) = refused(registry.promote(&chain, NOW));

        assert!(matches!(refusal, Refusal::BaseNotCurrent { .. }));
        assert_eq!(pointer, after_first);
    }

    #[test]
    fn rollback_returns_to_the_retained_checkpoint_and_is_logged() {
        let world = World::new();
        let dir = tempfile::tempdir().unwrap();
        let registry = registry(&world, dir.path());
        let draft = first_patch(&world, &registry);
        let chain = draft.sign();
        moved(registry.promote(&chain, NOW));

        let (release, pointer) = moved(registry.rollback(&order(&world, &registry), NOW + 2));

        assert_eq!(pointer.current, world.genesis());
        assert_eq!(
            pointer.previous,
            Previous::Checkpoint {
                digest: digest_of(&draft.output_file)
            }
        );
        assert_eq!(pointer.generation, 2);
        let opened = open::<ReleaseReceipt>(&release, registry.key()).unwrap();
        assert!(matches!(
            opened.body().transition,
            Transition::Rollback { .. }
        ));
        assert_eq!(replay(&world, &registry).unwrap(), pointer);

        // The promotion's evidence does not work a second time: the base is
        // current again, but nothing in that chain cites the rollback.
        let (refusal, _) = refused(registry.promote(&chain, NOW + 3));
        assert_eq!(refusal, Refusal::LineageMismatch);
    }

    #[test]
    fn a_rollback_order_from_the_editor_is_refused() {
        let world = World::new();
        let dir = tempfile::tempdir().unwrap();
        let registry = registry(&world, dir.path());
        let (_, after_first) = moved(registry.promote(&first_patch(&world, &registry).sign(), NOW));
        let forged = seal(
            &RollbackOrder {
                generation: 1,
                to: world.genesis(),
                policy: world.policy.digest(),
                not_after_micros: NOW + 1000,
            },
            &world.editor,
            "spiffe://test/editor",
            NOW + 1,
        )
        .unwrap();

        let (refusal, pointer) = refused(registry.rollback(&forged, NOW + 2));

        assert_eq!(
            refusal,
            Refusal::UntrustedSigner {
                hop: Hop::RollbackOrder
            }
        );
        assert_eq!(pointer, after_first);
    }

    #[test]
    fn a_second_round_needs_a_fresh_grant_that_cites_the_first_release() {
        let world = World::new();
        let dir = tempfile::tempdir().unwrap();
        let registry = registry(&world, dir.path());
        let first = first_patch(&world, &registry);
        let (_, after_first) = moved(registry.promote(&first.sign(), NOW));

        // The promoted checkpoint is the next base.
        let second = |pointer: &PointerState| {
            Draft::honest(
                &world,
                pointer,
                &first.output_file,
                &["layer.1.bias"],
                &["layer.1.bias"],
            )
        };

        // A grant that does not cite the first release.
        let mut uncited = second(&after_first);
        uncited.grant.lineage = Lineage::First;
        let (refusal, _) = refused(registry.promote(&uncited.sign(), NOW + 1));
        assert_eq!(refusal, Refusal::LineageMismatch);

        // The first round's grant, reused for a new manifest: it is scoped
        // to the old base.
        let mut reused = second(&after_first);
        reused.grant = first.grant.clone();
        let (refusal, _) = refused(registry.promote(&reused.sign(), NOW + 1));
        assert!(matches!(refusal, Refusal::BaseNotCurrent { .. }));

        // A fresh grant, scoped to the new base, citing the release.
        let fresh = second(&after_first);
        assert_eq!(
            fresh.grant.lineage,
            Lineage::After {
                release: match after_first.head {
                    Head::Release { receipt } => receipt,
                    Head::Genesis => panic!("the pointer moved"),
                }
            }
        );
        let (_, pointer) = moved(registry.promote(&fresh.sign(), NOW + 1));
        assert_eq!(pointer.generation, 2);
        assert_eq!(pointer.current, digest_of(&fresh.output_file));
        assert_eq!(
            pointer.previous,
            Previous::Checkpoint {
                digest: after_first.current
            }
        );
        assert_eq!(replay(&world, &registry).unwrap(), pointer);
    }

    #[test]
    fn a_move_interrupted_after_its_record_is_finished_on_open() {
        let world = World::new();
        let dir = tempfile::tempdir().unwrap();
        let registry = registry(&world, dir.path());
        let before = registry.pointer().unwrap();
        let (_, after_move) = moved(registry.promote(&first_patch(&world, &registry).sign(), NOW));
        // The crash: the record is in the log, the pointer was not replaced.
        registry.write_pointer(&before).unwrap();
        drop(registry);

        let reopened = reopen(&world, dir.path()).unwrap();

        assert_eq!(reopened.pointer().unwrap(), after_move);
    }

    #[test]
    fn a_pointer_the_log_does_not_explain_is_corrupt() {
        let world = World::new();
        let dir = tempfile::tempdir().unwrap();
        let registry = registry(&world, dir.path());
        let mut ahead = registry.pointer().unwrap();
        ahead.generation = 1;
        registry.write_pointer(&ahead).unwrap();
        drop(registry);
        assert!(matches!(
            reopen(&world, dir.path()),
            Err(RegistryError::Corrupt { .. })
        ));
    }

    #[test]
    fn a_registry_that_cannot_read_its_pointer_could_not_look() {
        let world = World::new();
        let dir = tempfile::tempdir().unwrap();
        let registry = registry(&world, dir.path());
        let chain = first_patch(&world, &registry).sign();
        fs::remove_file(dir.path().join(POINTER_FILE)).unwrap();
        assert!(matches!(
            registry.promote(&chain, NOW),
            MoveVerdict::CouldNotLook(RegistryError::Io(_))
        ));
        assert!(registry.records().unwrap().is_empty());
    }

    #[test]
    fn a_log_does_not_replay_under_another_key_or_with_other_evidence() {
        let world = World::new();
        let dir = tempfile::tempdir().unwrap();
        let registry = registry(&world, dir.path());
        let first = first_patch(&world, &registry);
        moved(registry.promote(&first.sign(), NOW));
        let records = registry.records().unwrap();

        assert!(matches!(
            audit(
                world.genesis(),
                &world.policy,
                RoleKey::of(&world.deployer),
                &records
            ),
            Err(AuditError::NotTheRegistrys { index: 0, .. })
        ));

        // A release receipt paired with a chain for a different candidate.
        let other = Draft::honest(
            &world,
            &PointerState::genesis(world.genesis()),
            &world.genesis_file,
            &["layer.1.bias"],
            &["layer.1.bias"],
        );
        let mut swapped = records.clone();
        swapped[0].evidence = Evidence::Promotion {
            chain: Box::new(other.sign()),
        };
        assert!(matches!(
            audit(
                world.genesis(),
                &world.policy,
                RoleKey::of(&world.registry),
                &swapped
            ),
            Err(AuditError::WrongMove { index: 0 })
        ));

        // Evidence that never justified a move.
        let mut unapproved = first_patch_at_genesis(&world);
        unapproved.approval = None;
        let mut unjustified = records;
        unjustified[0].evidence = Evidence::Promotion {
            chain: Box::new(unapproved.sign()),
        };
        assert!(matches!(
            audit(
                world.genesis(),
                &world.policy,
                RoleKey::of(&world.registry),
                &unjustified
            ),
            Err(AuditError::Unjustified {
                index: 0,
                refusal: Refusal::MissingApproval
            })
        ));
    }

    fn first_patch_at_genesis(world: &World) -> Draft {
        Draft::honest(
            world,
            &PointerState::genesis(world.genesis()),
            &world.genesis_file,
            &["layer.0.bias"],
            &["layer.0.bias"],
        )
    }
}
