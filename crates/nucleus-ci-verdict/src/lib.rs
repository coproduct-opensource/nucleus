//! The typed body for [`nucleus_receipt::Projection::Ci`].
//!
//! `nucleus-receipt` reserved this slot and said where the type belongs:
//!
//! > CI functor — a continuous-integration gate verdict… **The typed body
//! > lives in the consuming CI system**; this crate keeps it as
//! > `serde_json::Value` like every other projection.
//!
//! This is that body. The envelope already does signing, RFC 8785 canonical
//! bytes and verification, so none of that is re-implemented here.
//!
//! # The one discipline this crate exists to enforce
//!
//! A receipt is looked up by [`ActionKey`](nucleus_action_key), and answers for
//! **everything the key does not distinguish**. So every field of a verdict is
//! on exactly one of two sides:
//!
//! - **Keyed** — the action key already distinguishes it. Two runs differing
//!   here have different keys and never share a receipt.
//! - **Outcome** — what happened. Runs differing here legitimately share a key;
//!   that is what a cache *is*.
//!
//! Adding a field on the wrong side is a silent soundness hole. Put `arch` in
//! the struct without putting it in the action key, and an aarch64 receipt
//! answers an x86_64 check — a green tick for a run on different hardware,
//! with nothing anywhere reporting a problem.
//!
//! [`Classified::of`] is an **exhaustive destructure**, so a new field is an
//! `E0027` until someone states which side it is on. That is the same technique
//! `nucleus_spec::identity::program_digest` uses, and it is here for the same
//! reason: the failure it prevents is invisible at runtime.
//!
//! This mirrors the lesson gatehouse's `gate_def` learned the other way round —
//! hashing the *whole* struct meant resizing a pod's memory invalidated every
//! cached receipt. Too much on the keyed side costs hits; too little costs
//! soundness. Neither is a judgement anyone should make implicitly.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::panic,
        clippy::unreachable,
        clippy::todo
    )
)]

use serde::{Deserialize, Serialize};

pub mod verify;

/// What the gate answered.
///
/// Deliberately not a `bool`. A gate that could not run is not a gate that
/// passed — ADR 0007 A-2, "I could not look" is never "I looked and it was
/// fine" — and a two-valued type has nowhere to put that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Conclusion {
    /// The gate ran and passed.
    Success,
    /// The gate ran and failed.
    Failure,
    /// The gate did not run to completion. **Never cacheable as a pass**, and
    /// a caller that maps this to a green check has defeated the point.
    CouldNotLook,
}

impl Conclusion {
    /// Whether this verdict may answer a required check green.
    ///
    /// A free function rather than a caller's `== Success`, so the decision
    /// lives in one place and `CouldNotLook` cannot be folded into a pass by
    /// an inattentive match somewhere downstream.
    #[must_use]
    pub fn is_green(self) -> bool {
        match self {
            Conclusion::Success => true,
            Conclusion::Failure | Conclusion::CouldNotLook => false,
        }
    }
}

/// A CI gate verdict.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CiVerdict {
    /// Hex action key this verdict answers for. The store checks this against
    /// the key it was asked for; see `nucleus_receipt_store`.
    pub action_key: String,
    /// The required check name, e.g. `"Manifest Guards"`. Carried for humans
    /// and for the shadow lane's comparison — the key already covers it.
    pub context: String,
    /// Git tree oid the run happened at. **Reported, not keyed** — a receipt
    /// that only answered at its own tree would make every new pull request a
    /// total cold cache, which is the state gatehouse's `docs/hard-cut.md`
    /// records for its own receipts. Cross-tree reuse is the whole point, and
    /// the action key is what licenses it.
    pub tree: String,
    /// What the gate answered.
    pub conclusion: Conclusion,
    /// Process exit status, for a human reading a failure.
    pub exit_status: i32,
    /// Digest of the captured log. Lets an auditor fetch the log and confirm
    /// it is the one this verdict was minted from.
    pub log_digest: String,
    /// The pod that ran it.
    pub pod_id: String,
    /// Opaque evidence a public verifier **ignores**. Gatehouse's
    /// kernel-checked certificate rides here as a strictly additive upgrade;
    /// nucleus carries it as bytes it never interprets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<serde_json::Value>,
}

/// Which side of the cache boundary each field sits on.
///
/// Constructed only by [`Classified::of`], whose exhaustive destructure is the
/// point of the type.
#[derive(Debug)]
pub struct Classified<'a> {
    /// Fields the action key already distinguishes. Listed for audit, not for
    /// re-hashing — the key is the digest.
    pub keyed: Vec<(&'static str, &'a str)>,
    /// Fields describing what happened. Two runs may differ here and still
    /// share a receipt; that is what a cache is.
    pub outcome: Vec<&'static str>,
}

impl<'a> Classified<'a> {
    /// Assign every field of a verdict to a side.
    ///
    /// **Exhaustive destructure.** A new field on `CiVerdict` is an `E0027`
    /// here until someone writes down which side it belongs on. See the module
    /// docs for why that is worth a compile error.
    #[must_use]
    pub fn of(v: &'a CiVerdict) -> Self {
        let CiVerdict {
            action_key,
            context,
            // Bound as `_` because only the two keyed fields carry their value
            // into `Classified`; the outcome side lists names. The
            // `every_field_of_the_struct_is_classified_exactly_once` test reads
            // the field set out of serde, so a field silenced here still has to
            // appear on one of the two lists.
            tree: _,
            conclusion: _,
            exit_status: _,
            log_digest: _,
            pod_id: _,
            certificate: _,
        } = v;

        Self {
            // `action_key` IS the key; `context` is one of its inputs. Both are
            // distinguished by it, so two runs differing here never share a
            // receipt.
            keyed: vec![("action_key", action_key), ("context", context)],
            // `tree` is deliberately here and not above — see its field doc.
            outcome: vec![
                "tree",
                "conclusion",
                "exit_status",
                "log_digest",
                "pod_id",
                "certificate",
            ],
        }
    }
}

/// Errors reading a verdict back out of an envelope.
#[derive(Debug)]
pub enum VerdictError {
    /// The receipt carries no CI projection.
    NoCiProjection,
    /// It carries more than one, so which verdict it asserts is ambiguous.
    ManyCiProjections(usize),
    /// The CI body is not a `CiVerdict`.
    Malformed(String),
}

impl std::fmt::Display for VerdictError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerdictError::NoCiProjection => {
                write!(f, "this receipt carries no CI projection")
            }
            VerdictError::ManyCiProjections(n) => write!(
                f,
                "this receipt carries {n} CI projections, so which verdict it \
                 asserts is ambiguous — refusing to pick one"
            ),
            VerdictError::Malformed(e) => write!(f, "the CI projection is not a verdict: {e}"),
        }
    }
}

impl std::error::Error for VerdictError {}

impl CiVerdict {
    /// Wrap this verdict as a projection, ready to sign into an envelope.
    #[must_use]
    pub fn to_projection(&self) -> nucleus_receipt::Projection {
        // `serde_json::to_value` on a struct of strings and ints cannot fail;
        // the fallback keeps the panic-free declaration honest rather than
        // asserting the impossible with `unwrap`.
        let body = serde_json::to_value(self).unwrap_or(serde_json::Value::Null);
        nucleus_receipt::Projection::Ci(body)
    }

    /// The single CI verdict in a receipt.
    ///
    /// Refuses a receipt carrying two, rather than taking the first. A receipt
    /// that asserts two verdicts has no determinate answer, and picking one
    /// silently is how a caller ends up reading the wrong half.
    ///
    /// This does **not** verify the signature — call
    /// [`nucleus_receipt::Receipt::verify`] first. Said here rather than
    /// implied by silence.
    pub fn from_receipt(r: &nucleus_receipt::Receipt) -> Result<Self, VerdictError> {
        let mut bodies = r.projections.iter().filter_map(|p| match p {
            nucleus_receipt::Projection::Ci(b) => Some(b),
            _ => None,
        });
        let first = bodies.next().ok_or(VerdictError::NoCiProjection)?;
        let extra = bodies.count();
        if extra > 0 {
            return Err(VerdictError::ManyCiProjections(extra.saturating_add(1)));
        }
        serde_json::from_value(first.clone()).map_err(|e| VerdictError::Malformed(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_receipt::{Receipt, Session};

    fn verdict() -> CiVerdict {
        CiVerdict {
            action_key: "ad85d4e3ebdad2ed".repeat(4),
            context: "Manifest Guards".into(),
            tree: "4b825dc642cb6eb9a060e54bf8d69288fbee4904".into(),
            conclusion: Conclusion::Success,
            exit_status: 0,
            log_digest: "ab".repeat(32),
            pod_id: "pod-1".into(),
            certificate: None,
        }
    }

    fn session() -> Session {
        Session {
            session_id: "spiffe://nucleus/node/1".into(),
            issuer_kid: "kid-1".into(),
            issued_at_micros: 1_757_000_000_000_000,
            parent_chain: vec![],
        }
    }

    fn key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    /// **The assembled-thing test.** Each half is obviously fine; the question
    /// is whether a verdict survives being signed into a real envelope and
    /// verified out of it. That question is how two composition gaps were found
    /// already (a protocol command nothing sent; a receipt `build()` nothing
    /// verified), so it gets asked first here.
    #[test]
    fn a_verdict_signed_into_an_envelope_verifies_and_comes_back_whole() {
        let v = verdict();
        let sk = key();
        let receipt = Receipt::sign(session(), vec![v.to_projection()], &sk);

        receipt
            .verify(&sk.verifying_key().to_bytes())
            .expect("the envelope this test just signed must verify");

        let back = CiVerdict::from_receipt(&receipt).expect("a CI projection is present");
        assert_eq!(back, v, "the verdict must survive the round trip unchanged");
    }

    #[test]
    fn a_verdict_does_not_verify_under_another_key() {
        let receipt = Receipt::sign(session(), vec![verdict().to_projection()], &key());
        let other = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        assert!(
            receipt.verify(&other.verifying_key().to_bytes()).is_err(),
            "a receipt must not verify under a key that did not sign it"
        );
    }

    /// A tampered verdict must not verify. The envelope covers the projection
    /// bodies, so this is really a test that the CI body is inside the signed
    /// bytes and not alongside them.
    #[test]
    fn flipping_the_conclusion_breaks_the_signature() {
        let sk = key();
        let mut receipt = Receipt::sign(session(), vec![verdict().to_projection()], &sk);

        let mut tampered = verdict();
        tampered.conclusion = Conclusion::Failure;
        receipt.projections = vec![tampered.to_projection()];

        assert!(
            receipt.verify(&sk.verifying_key().to_bytes()).is_err(),
            "a flipped verdict must break the signature, or the body is not covered by it"
        );
    }

    #[test]
    fn two_ci_projections_are_refused_rather_than_the_first_one_taken() {
        let receipt = Receipt::sign(
            session(),
            vec![verdict().to_projection(), verdict().to_projection()],
            &key(),
        );
        match CiVerdict::from_receipt(&receipt) {
            Err(VerdictError::ManyCiProjections(2)) => {}
            other => panic!("expected a refusal to pick one, got {other:?}"),
        }
    }

    #[test]
    fn a_receipt_with_no_ci_projection_is_not_a_verdict() {
        let receipt = Receipt::sign(
            session(),
            vec![nucleus_receipt::Projection::Identity(serde_json::json!({}))],
            &key(),
        );
        assert!(matches!(
            CiVerdict::from_receipt(&receipt),
            Err(VerdictError::NoCiProjection)
        ));
    }

    /// Every field of the struct is classified, and none is on both sides.
    ///
    /// The expected field set is read back out of the **serialized verdict**,
    /// not written here as a literal count. That matters: `E0027` forces
    /// `Classified::of` to mention a new field, but the compiler itself
    /// suggests `arch: _` as a way to silence it, and a literal count sails
    /// straight past that. A first draft of this test asserted `== 8` and a
    /// field added as `arch: _` passed every test in the crate — a gate that
    /// cannot fail, which ADR 0007 I-1 forbids. Deriving the set from serde
    /// closes it: a silenced field is now a named, missing field.
    #[test]
    fn every_field_of_the_struct_is_classified_exactly_once() {
        let mut v = verdict();
        // `certificate` is `skip_serializing_if`, so give it a value or it is
        // absent from the serialized form and silently escapes this check.
        v.certificate = Some(serde_json::json!({"opaque": true}));

        let serde_json::Value::Object(fields) = serde_json::to_value(&v).expect("serializable")
        else {
            panic!("a verdict must serialize to an object");
        };

        let c = Classified::of(&v);
        let keyed: Vec<&str> = c.keyed.iter().map(|(n, _)| *n).collect();

        for k in &keyed {
            assert!(
                !c.outcome.contains(k),
                "{k} is on both sides; a field cannot be both keyed and outcome"
            );
        }

        let mut classified: Vec<&str> = keyed.clone();
        classified.extend_from_slice(&c.outcome);
        classified.sort_unstable();

        let mut actual: Vec<&str> = fields.keys().map(String::as_str).collect();
        actual.sort_unstable();

        assert_eq!(
            classified, actual,
            "every field of CiVerdict must appear on exactly one side — an \
             unclassified field is a receipt answering for a difference the \
             action key does not distinguish"
        );
    }

    #[test]
    fn could_not_look_is_never_green() {
        assert!(Conclusion::Success.is_green());
        assert!(!Conclusion::Failure.is_green());
        assert!(
            !Conclusion::CouldNotLook.is_green(),
            "A-2: 'I could not look' is never 'I looked and it was fine'"
        );
    }
}
