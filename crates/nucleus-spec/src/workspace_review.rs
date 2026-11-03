//! The operator's declaration that a pod's workspace is a review-gated private
//! copy (ADR 0014 §10, amended 2026-10-29).
//!
//! # What the operator promises by declaring it
//!
//! That the pod's workspace is the cell's own copy, and that nothing written in
//! it is built, run, installed or merged outside a sandbox until a person has
//! reviewed it: for instance, changes leave only as a proposal that is re-checked
//! in a fresh pod and merged by a person. Nucleus cannot observe that pipeline,
//! so it does not verify the promise; it takes the operator at their word, the
//! way it takes a policy profile, and the declaration is in the spec where a
//! reader of the signed receipt sees it.
//!
//! What follows from it, and nothing more: a `write_files` or `edit_files` in a
//! session that has read untrusted content is no longer refused by the egress
//! gate as an outbound sink, because the bytes stay in the cell. Capabilities,
//! path scope, approval obligations, budget and Cedar still decide the write.
//! Every other operation is decided as before.
//!
//! # Where it is written, and why there
//!
//! The label [`REVIEW_GATED_LABEL`], for the reason `isolation_profile` gives:
//! the guest's tool-proxy parses the spec with `deny_unknown_fields`, so a new
//! `PodSpecInner` field would make every declaring pod unparseable by the
//! pinned guest release, while labels are already in the spec every published
//! guest reads, and in the program identity whole. Host and guest therefore read
//! the same declaration from the same bytes.
//!
//! # No default that grants (ADR 0007 B)
//!
//! Absent, or `"false"`, is [`WorkspaceReview::Unreviewed`], which grants
//! nothing. Any other spelling is refused, never read as either: a typo must not
//! decide what a write may do.

use portcullis::kernel::WorkspaceReview;

use crate::PodSpec;

/// The label a pod spec declares a review-gated workspace in.
pub const REVIEW_GATED_LABEL: &str = "workspace.coproduct.one/review-gated";

/// The declaration `spec` makes. The one decider.
///
/// # Errors
///
/// [`UnknownReview`] when the label is present and is neither `"true"` nor
/// `"false"`.
pub fn of(spec: &PodSpec) -> Result<WorkspaceReview, UnknownReview> {
    match spec
        .metadata
        .labels
        .get(REVIEW_GATED_LABEL)
        .map(String::as_str)
    {
        None | Some("false") => Ok(WorkspaceReview::Unreviewed),
        Some("true") => Ok(WorkspaceReview::ReviewGated),
        Some(other) => Err(UnknownReview {
            value: other.to_string(),
        }),
    }
}

/// A value of [`REVIEW_GATED_LABEL`] that is neither `true` nor `false`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "{REVIEW_GATED_LABEL} is `{value}`, which is neither `true` nor `false`; it is refused \
     rather than read as either"
)]
pub struct UnknownReview {
    /// The spelling that did not parse.
    pub value: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(label: Option<&str>) -> PodSpec {
        let mut spec: PodSpec =
            serde_json::from_str(r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{"policy":{"type":"profile","name":"default"}}}"#)
                .expect("a minimal spec parses");
        if let Some(v) = label {
            spec.metadata
                .labels
                .insert(REVIEW_GATED_LABEL.into(), v.into());
        }
        spec
    }

    #[test]
    fn only_true_declares_and_only_true_or_false_parses() {
        assert_eq!(of(&spec(None)), Ok(WorkspaceReview::Unreviewed));
        assert_eq!(of(&spec(Some("false"))), Ok(WorkspaceReview::Unreviewed));
        assert_eq!(of(&spec(Some("true"))), Ok(WorkspaceReview::ReviewGated));
        for bad in ["", "TRUE", "True", "yes", "1", "true "] {
            assert_eq!(
                of(&spec(Some(bad))),
                Err(UnknownReview { value: bad.into() }),
                "{bad:?} must be refused"
            );
        }
    }

    /// The declaration is a label, so a spec carrying it still parses under the
    /// spec types every published guest has: nothing new in `PodSpecInner`.
    #[test]
    fn a_declaring_spec_parses_as_any_other() {
        let json = format!(
            r#"{{"apiVersion":"nucleus/v1","kind":"Pod",
                "metadata":{{"labels":{{"{REVIEW_GATED_LABEL}":"true"}}}},"spec":{{"policy":{{"type":"profile","name":"default"}}}}}}"#
        );
        let parsed: PodSpec = serde_json::from_str(&json).expect("parses");
        assert_eq!(of(&parsed), Ok(WorkspaceReview::ReviewGated));
        // The field shape a spec author might reach for first is refused by the
        // spec type the guest parses with, which is why this is a label.
        let field = r#"{"apiVersion":"nucleus/v1","kind":"Pod",
            "spec":{"policy":{"type":"profile","name":"default"},"workspace":{"review_gated":true}}}"#;
        assert!(serde_json::from_str::<PodSpec>(field).is_err());
    }
}
