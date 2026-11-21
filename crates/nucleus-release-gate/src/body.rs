//! The bodies of the chain, and the only two ways to move one in or out of a
//! signed receipt.
//!
//! [`seal`] puts a body in a `nucleus_receipt::Receipt` under a schema name.
//! [`open`] takes one out, and returns it only if the receipt verifies under a
//! key **the caller supplies**, names that key as its issuer, and holds exactly
//! one body of the expected schema with no field this reader does not know.
//! The key is never read from the receipt being checked.

use ed25519_dalek::SigningKey;
use nucleus_receipt::{Projection, Receipt, Session};
use nucleus_weight_patch::{CheckpointDigest, DeclaredWrites, ProgramDigest, TensorWrite};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::chain::Refusal;
use crate::eval::EvalResults;
use crate::keys::{ContentDigest, PolicyDigest, ReceiptHash, RoleKey};

/// Which projection of the receipt envelope a body travels in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carrier {
    /// A grant of, or a decision about, authority.
    Capability,
    /// What a run was asked and what it answered.
    Run,
}

mod sealed {
    pub trait Sealed {}
}

/// A body of the weight-patch chain. Implemented only in this crate.
pub trait Body: Serialize + DeserializeOwned + sealed::Sealed {
    /// The schema name written beside the body and required when reading it.
    const SCHEMA: &'static str;
    /// The projection it travels in.
    const CARRIER: Carrier;
}

macro_rules! body {
    ($ty:ident, $schema:literal, $carrier:ident) => {
        impl sealed::Sealed for $ty {}
        impl Body for $ty {
            const SCHEMA: &'static str = $schema;
            const CARRIER: Carrier = Carrier::$carrier;
        }
    };
}

/// How many runs, and how much accelerator time, a grant allows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunBudget {
    /// Applications of a patch the runner may perform under the grant.
    pub max_runs: u32,
    /// Accelerator seconds an evaluation under the grant may use.
    pub max_accelerator_seconds: u64,
}

/// Where a grant sits in the history of releases.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "lineage", rename_all = "snake_case", deny_unknown_fields)]
pub enum Lineage {
    /// The base is the checkpoint the registry was created with.
    First,
    /// The base was put in place by this release or rollback receipt.
    After {
        /// That receipt.
        release: ReceiptHash,
    },
}

/// Authority to propose changes to one base checkpoint. Signed by a deployer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalGrant {
    /// The key that may sign manifests under this grant.
    pub editor: RoleKey,
    /// The one checkpoint the grant is about.
    pub base: CheckpointDigest,
    /// The policy the grant was issued under.
    pub policy: PolicyDigest,
    /// What the editor may spend.
    pub budget: RunBudget,
    /// The last microsecond at which the grant holds.
    pub not_after_micros: u64,
    /// The release that made `base` current.
    pub lineage: Lineage,
}
body!(ProposalGrant, "nucleus.weight_patch.grant.v1", Capability);

/// A proposed change. Signed by the editor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchManifest {
    /// The grant this is proposed under.
    pub grant: ReceiptHash,
    /// The checkpoint the program is to be applied to.
    pub base: CheckpointDigest,
    /// The program.
    pub program: ProgramDigest,
    /// Every tensor the editor says the program writes.
    pub declared: DeclaredWrites,
    /// The checkpoint the editor says will result.
    pub expected_output: CheckpointDigest,
}
body!(
    PatchManifest,
    "nucleus.weight_patch.manifest.v1",
    Capability
);

/// What happened when the runner applied a manifest's program.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum ApplyOutcome {
    /// The program ran, wrote only declared tensors, and produced the
    /// expected checkpoint.
    Applied {
        /// The measured output digest.
        output: CheckpointDigest,
        /// The measured writes.
        writes: Vec<TensorWrite>,
    },
    /// The program wrote a tensor the manifest did not declare.
    WriteSetViolation {
        /// The undeclared tensors.
        undeclared: Vec<String>,
        /// Every measured write.
        writes: Vec<TensorWrite>,
    },
    /// The program ran within its declaration and produced a different
    /// checkpoint from the one the manifest expects.
    OutputMismatch {
        /// What the manifest expects.
        expected: CheckpointDigest,
        /// What was measured.
        actual: CheckpointDigest,
    },
    /// The program could not be applied to the files the runner was given.
    CouldNotApply {
        /// Why.
        reason: String,
    },
}

/// The runner's account of one application. Signed by a runner, for failures
/// as well as successes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyReceipt {
    /// The manifest that was applied.
    pub manifest: ReceiptHash,
    /// The base the manifest names.
    pub base: CheckpointDigest,
    /// The program the manifest names.
    pub program: ProgramDigest,
    /// Which run under the grant this was, counting from one.
    pub run: u32,
    /// What happened.
    pub outcome: ApplyOutcome,
}
body!(ApplyReceipt, "nucleus.weight_patch.apply.v1", Run);

/// The evaluation suite: its content and the version label it is known by.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuiteId {
    /// The suite's content digest.
    pub digest: ContentDigest,
    /// Its version label.
    pub version: String,
}

/// The decoding settings, in integers so two parties cannot disagree about
/// them in the last decimal place.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decoding {
    /// Temperature, in thousandths.
    pub temperature_milli: u32,
    /// Nucleus-sampling mass, in thousandths.
    pub top_p_milli: u32,
    /// The number of highest-probability tokens sampled from.
    pub top_k: u32,
    /// The most tokens one answer may use.
    pub max_tokens: u32,
}

/// The evaluator's measurement of one candidate against its base. Signed by an
/// evaluator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalReceipt {
    /// The apply receipt whose output was evaluated.
    pub apply: ReceiptHash,
    /// The base that was run.
    pub base: CheckpointDigest,
    /// The candidate that was run, as the evaluator measured it.
    pub candidate: CheckpointDigest,
    /// The suite.
    pub suite: SuiteId,
    /// The decoding settings, the same for base and candidate.
    pub decoding: Decoding,
    /// The seed list, the same for base and candidate.
    pub seeds: ContentDigest,
    /// The harness image that produced the answers.
    pub harness: ContentDigest,
    /// The per-item outcomes the results were computed from.
    pub transcript: ContentDigest,
    /// Accelerator seconds the evaluation used.
    pub accelerator_seconds: u64,
    /// The results.
    pub results: EvalResults,
}
body!(EvalReceipt, "nucleus.weight_patch.eval.v1", Run);

/// A deployer's approval of one candidate for one move of the pointer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    /// The evaluation the approval rests on.
    pub eval: ReceiptHash,
    /// The candidate approved.
    pub candidate: CheckpointDigest,
    /// The policy it was approved under.
    pub policy: PolicyDigest,
    /// The pointer generation this approval replaces. The pointer has each
    /// generation once, so an approval moves it at most once.
    pub generation: u64,
    /// The last microsecond at which the approval holds.
    pub not_after_micros: u64,
}
body!(Approval, "nucleus.weight_patch.approval.v1", Capability);

/// A deployer's order to return to the previous checkpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackOrder {
    /// The pointer generation this order replaces.
    pub generation: u64,
    /// The checkpoint to return to. It must be the one the pointer retains.
    pub to: CheckpointDigest,
    /// The policy the order was issued under.
    pub policy: PolicyDigest,
    /// The last microsecond at which the order holds.
    pub not_after_micros: u64,
}
body!(
    RollbackOrder,
    "nucleus.weight_patch.rollback_order.v1",
    Capability
);

/// Why the pointer moved.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "transition", rename_all = "snake_case", deny_unknown_fields)]
pub enum Transition {
    /// A candidate was promoted on this evidence.
    Promotion {
        /// The proposal grant.
        grant: ReceiptHash,
        /// The patch manifest.
        manifest: ReceiptHash,
        /// The apply receipt.
        apply: ReceiptHash,
        /// The evaluation receipt.
        eval: ReceiptHash,
        /// The approval.
        approval: ReceiptHash,
    },
    /// The previous checkpoint was restored on this order.
    Rollback {
        /// The rollback order.
        order: ReceiptHash,
    },
}

/// One move of the serving pointer. Signed by the registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseReceipt {
    /// What was being served.
    pub previous: CheckpointDigest,
    /// What is served now.
    pub current: CheckpointDigest,
    /// The pointer's generation after the move.
    pub generation: u64,
    /// Why it moved.
    pub transition: Transition,
}
body!(
    ReleaseReceipt,
    "nucleus.weight_patch.release.v1",
    Capability
);

/// A refused attempt to move the pointer, as the registry recorded it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefusalNotice {
    /// The checkpoint that stayed in place.
    pub current: CheckpointDigest,
    /// The pointer's generation, unchanged.
    pub generation: u64,
    /// Why the attempt was refused.
    pub refusal: Refusal,
}
body!(RefusalNotice, "nucleus.weight_patch.refusal.v1", Capability);

#[derive(Serialize)]
struct WireOut<'a, B> {
    schema: &'a str,
    body: &'a B,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireIn<B> {
    schema: String,
    body: B,
}

/// Why a body could not be sealed.
#[derive(Debug, thiserror::Error)]
pub enum SealError {
    /// The body did not serialize.
    #[error("serializing the body: {0}")]
    Json(#[from] serde_json::Error),
    /// The body holds an integer with no exact canonical form.
    #[error("the integer at {path} has no exact canonical form")]
    InexactInteger {
        /// Where it is.
        path: String,
    },
}

/// Signs `body` as `signer`.
///
/// The time is an argument: nothing in this crate reads a clock.
///
/// # Errors
///
/// [`SealError`] if the body cannot be put in canonical form.
pub fn seal<B: Body>(
    body: &B,
    signer: &SigningKey,
    session_id: &str,
    issued_at_micros: u64,
) -> Result<Receipt, SealError> {
    let value = serde_json::to_value(WireOut {
        schema: B::SCHEMA,
        body,
    })?;
    if let Some(path) = nucleus_receipt::jcs_inexact_integer(&value) {
        return Err(SealError::InexactInteger { path });
    }
    let projection = match B::CARRIER {
        Carrier::Capability => Projection::Capability(value),
        Carrier::Run => Projection::Ci(value),
    };
    let session = Session {
        session_id: session_id.to_owned(),
        issuer_kid: RoleKey::of(signer).to_hex(),
        issued_at_micros,
        parent_chain: Vec::new(),
    };
    Ok(Receipt::sign(session, vec![projection], signer))
}

/// Why a receipt did not yield a body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "error", rename_all = "snake_case", deny_unknown_fields)]
pub enum OpenError {
    /// The signature, root hash or version did not verify under the key.
    #[error("the receipt does not verify under the expected key: {detail}")]
    Signature {
        /// The verifier's message.
        detail: String,
    },
    /// The receipt verifies but names a different issuer key.
    #[error("the receipt names a different issuer key")]
    IssuerMismatch,
    /// The receipt does not hold exactly one body.
    #[error("the receipt holds {count} bodies; a chain receipt holds one")]
    BodyCount {
        /// How many it holds.
        count: usize,
    },
    /// The body is in the wrong projection, or under another schema name.
    #[error("the receipt holds a body of another kind")]
    WrongKind,
    /// The body does not parse as its schema.
    #[error("the body does not parse: {detail}")]
    Malformed {
        /// The parser's message.
        detail: String,
    },
}

/// A body taken out of a receipt that verified.
///
/// Minted only by [`open`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opened<B> {
    body: B,
    hash: ReceiptHash,
    signer: RoleKey,
    issued_at_micros: u64,
}

impl<B> Opened<B> {
    /// The body.
    pub const fn body(&self) -> &B {
        &self.body
    }

    /// The receipt's root hash.
    pub const fn hash(&self) -> ReceiptHash {
        self.hash
    }

    /// The key the receipt verified under.
    pub const fn signer(&self) -> RoleKey {
        self.signer
    }

    /// When the signer says it signed.
    pub const fn issued_at_micros(&self) -> u64 {
        self.issued_at_micros
    }
}

/// Verifies `receipt` under `signer` and returns its body.
///
/// # Errors
///
/// [`OpenError`] if the receipt does not verify under `signer`, names another
/// issuer, or does not hold exactly one well-formed body of schema `B`.
pub fn open<B: Body>(receipt: &Receipt, signer: RoleKey) -> Result<Opened<B>, OpenError> {
    receipt
        .verify_strict(signer.as_bytes())
        .map_err(|e| OpenError::Signature {
            detail: e.to_string(),
        })?;
    if receipt.session.issuer_kid != signer.to_hex() {
        return Err(OpenError::IssuerMismatch);
    }
    let [projection] = receipt.projections.as_slice() else {
        return Err(OpenError::BodyCount {
            count: receipt.projections.len(),
        });
    };
    let value = match (B::CARRIER, projection) {
        (Carrier::Capability, Projection::Capability(value))
        | (Carrier::Run, Projection::Ci(value)) => value,
        // Every other pairing, including projections this crate does not
        // know, is not this body.
        (Carrier::Capability | Carrier::Run, _) => return Err(OpenError::WrongKind),
    };
    // The schema is read first and alone, so a body of another kind is
    // reported as that and not as a parse failure of this one.
    let schema = value.get("schema").and_then(serde_json::Value::as_str);
    if schema != Some(B::SCHEMA) {
        return Err(OpenError::WrongKind);
    }
    let wire = WireIn::<B>::deserialize(value).map_err(|e| OpenError::Malformed {
        detail: e.to_string(),
    })?;
    let WireIn { schema, body } = wire;
    if schema != B::SCHEMA {
        return Err(OpenError::WrongKind);
    }
    // The root hash was recomputed by `verify_strict`; it is hexadecimal.
    let hash = receipt
        .root_hash_hex
        .parse()
        .map_err(|_| OpenError::Signature {
            detail: "the root hash is not 64 lowercase hexadecimal characters".to_owned(),
        })?;
    Ok(Opened {
        body,
        hash,
        signer,
        issued_at_micros: receipt.session.issued_at_micros,
    })
}

/// The key a receipt names as its issuer, for choosing which trusted key to
/// verify it under. Naming a key proves nothing; [`open`] does the proving.
#[must_use]
pub fn named_issuer(receipt: &Receipt) -> Option<RoleKey> {
    receipt.session.issuer_kid.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }

    fn order() -> RollbackOrder {
        RollbackOrder {
            generation: 3,
            to: "11".repeat(32).parse().unwrap(),
            policy: "22".repeat(32).parse().unwrap(),
            not_after_micros: 9,
        }
    }

    #[test]
    fn a_sealed_body_opens_under_its_signer() {
        let receipt = seal(&order(), &key(1), "spiffe://example/deployer", 5).unwrap();
        let opened: Opened<RollbackOrder> = open(&receipt, RoleKey::of(&key(1))).unwrap();
        assert_eq!(opened.body(), &order());
        assert_eq!(opened.signer(), RoleKey::of(&key(1)));
        assert_eq!(opened.issued_at_micros(), 5);
        assert_eq!(opened.hash().to_hex(), receipt.root_hash_hex);
    }

    #[test]
    fn another_key_does_not_open_it() {
        let receipt = seal(&order(), &key(1), "spiffe://example/deployer", 5).unwrap();
        assert!(matches!(
            open::<RollbackOrder>(&receipt, RoleKey::of(&key(2))),
            Err(OpenError::Signature { .. })
        ));
    }

    #[test]
    fn a_changed_body_does_not_open() {
        let mut receipt = seal(&order(), &key(1), "spiffe://example/deployer", 5).unwrap();
        let Some(Projection::Capability(value)) = receipt.projections.first_mut() else {
            panic!("a rollback order travels as a capability");
        };
        value["body"]["generation"] = 4.into();
        assert!(matches!(
            open::<RollbackOrder>(&receipt, RoleKey::of(&key(1))),
            Err(OpenError::Signature { .. })
        ));
    }

    #[test]
    fn a_body_of_another_kind_is_not_this_one() {
        let receipt = seal(&order(), &key(1), "spiffe://example/deployer", 5).unwrap();
        assert_eq!(
            open::<Approval>(&receipt, RoleKey::of(&key(1))),
            Err(OpenError::WrongKind)
        );
        assert_eq!(
            open::<ApplyReceipt>(&receipt, RoleKey::of(&key(1))),
            Err(OpenError::WrongKind)
        );
    }

    #[test]
    fn a_receipt_with_two_bodies_is_refused() {
        let one = seal(&order(), &key(1), "spiffe://example/deployer", 5).unwrap();
        let both = Receipt::sign(
            one.session.clone(),
            vec![one.projections[0].clone(), one.projections[0].clone()],
            &key(1),
        );
        assert_eq!(
            open::<RollbackOrder>(&both, RoleKey::of(&key(1))),
            Err(OpenError::BodyCount { count: 2 })
        );
    }

    #[test]
    fn an_unknown_field_is_refused_even_when_signed() {
        let value = serde_json::json!({
            "schema": RollbackOrder::SCHEMA,
            "body": {
                "generation": 3,
                "to": "11".repeat(32),
                "policy": "22".repeat(32),
                "not_after_micros": 9,
                "also": true,
            },
        });
        let session = Session {
            session_id: "spiffe://example/deployer".to_owned(),
            issuer_kid: RoleKey::of(&key(1)).to_hex(),
            issued_at_micros: 5,
            parent_chain: Vec::new(),
        };
        let receipt = Receipt::sign(session, vec![Projection::Capability(value)], &key(1));
        assert!(matches!(
            open::<RollbackOrder>(&receipt, RoleKey::of(&key(1))),
            Err(OpenError::Malformed { .. })
        ));
    }

    #[test]
    fn an_integer_with_no_exact_form_is_not_sealed() {
        let mut too_big = order();
        too_big.generation = u64::MAX;
        assert!(matches!(
            seal(&too_big, &key(1), "spiffe://example/deployer", 5),
            Err(SealError::InexactInteger { .. })
        ));
    }
}
