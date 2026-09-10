//! What a combination of exposure legs *permits*.
//!
//! Every disclosure level said the same two things about risk: a grade, and a
//! count of legs.
//!
//! ```text
//! Risk:    2 of 3 exposure legs (private data + untrusted content); exfiltration absent → no approval prompts expected
//! ```
//!
//! Two of three what? The sentence a person actually needs — *this combination
//! permits repository data to leave the sandbox* — existed at no level, in no
//! renderer. Yet the material was all there and thrown away: [`state_risk`]
//! computes the three legs as named booleans and collapses them to a count on
//! the next line, and [`UninhabitableState`] carries a `name` for exactly this
//! purpose that no renderer has ever read.
//!
//! This module keeps the identities. [`mechanism`] answers "what does *this*
//! combination let the agent do", for all eight subsets, and [`risk_line`]
//! renders the whole line from a [`RiskSummary`].
//!
//! # Why the legs are separate from the grade
//!
//! [`StateRisk`] is ordered and load-bearing: the kernel gates on it and the
//! Lean development reasons about it. Nothing here changes what it computes.
//! The mechanism is rendering — an English gloss on a set — and is kept out of
//! the grade's way on purpose.
//!
//! [`state_risk`]: crate::IncompatibilityConstraint::state_risk
//! [`UninhabitableState`]: crate::uninhabitable_state::UninhabitableState

use crate::task_grant::RiskSummary;
use crate::ExposureLabel;

/// What the combination of legs permits, in one clause.
///
/// The eight subsets are spelled out rather than composed from per-leg
/// fragments, because the interesting content is in the *joins*: "the agent
/// can read private data" and "the agent can reach the network" are two facts,
/// and "whatever it reads can leave" is the third fact that only exists when
/// both hold. A generated sentence would have said the first two and lost the
/// one worth reading.
///
/// Written as a match on the triple with no catch-all: a fourth leg would fail
/// to compile here rather than quietly inherit the nearest sentence.
#[must_use]
pub fn mechanism(legs: &[ExposureLabel]) -> &'static str {
    let private = legs.contains(&ExposureLabel::PrivateData);
    let untrusted = legs.contains(&ExposureLabel::UntrustedContent);
    let exfil = legs.contains(&ExposureLabel::ExfilVector);

    match (private, untrusted, exfil) {
        (false, false, false) => "nothing the agent can reach is private, untrusted or outbound",
        (true, false, false) => {
            "the agent can read private data, but nothing steers what it reads and nothing carries it out"
        }
        (false, true, false) => {
            "the agent can read untrusted content, but holds nothing private and has no way out"
        }
        (false, false, true) => {
            "the agent can send data out of the sandbox, but has nothing private to send and nothing directing it"
        }
        (true, true, false) => {
            "untrusted content can steer what the agent reads, but nothing granted carries what it reads out of the sandbox"
        }
        (true, false, true) => {
            "whatever the agent can read can leave the sandbox, but nothing untrusted directs what it reads"
        }
        (false, true, true) => {
            "untrusted content can direct what the agent sends out of the sandbox, but it holds no private data to send"
        }
        (true, true, true) => {
            "untrusted content can direct the agent to read private data and send it out of the sandbox"
        }
    }
}

/// The whole `Risk:` line.
///
/// Three clauses: which legs are present, what that combination permits, and
/// whether the kernel will stop to ask.
///
/// The third clause is read from `approval_gated`, which is the actual list of
/// operations carrying an obligation. It used to be inferred from the leg
/// count — three legs meant "the kernel asks", fewer meant the flat assertion
/// `no approval prompts expected`. That is a claim about the obligations made
/// without looking at them, and it is false for any grant whose obligations
/// were set by some route other than the trifecta: an effect pack that gates
/// an operation, a ceiling profile that does, a narrowed grant that inherited
/// one. Such a grant promised the person no prompts and then prompted.
#[must_use]
pub fn risk_line(risk: &RiskSummary) -> String {
    let legs = risk.exposure_legs.len();
    let present: Vec<&str> = risk.exposure_legs.iter().map(|l| leg_name(*l)).collect();

    let mut line = if legs == 3 {
        format!("all 3 exposure legs present ({})", present.join(" + "))
    } else {
        let missing: Vec<&str> = [
            ExposureLabel::PrivateData,
            ExposureLabel::UntrustedContent,
            ExposureLabel::ExfilVector,
        ]
        .iter()
        .filter(|l| !risk.exposure_legs.contains(l))
        .map(|l| leg_name(*l))
        .collect();
        let with = if present.is_empty() {
            String::new()
        } else {
            format!(" ({})", present.join(" + "))
        };
        format!(
            "{legs} of 3 exposure legs{with}; {} absent",
            missing.join(" and ")
        )
    };

    line.push_str(" → ");
    line.push_str(mechanism(&risk.exposure_legs));

    if risk.approval_gated.is_empty() {
        line.push_str("; no approval prompts expected");
    } else {
        let gated: Vec<String> = risk
            .approval_gated
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        line.push_str("; the kernel asks for approval before ");
        line.push_str(&gated.join(", "));
    }
    line
}

fn leg_name(l: ExposureLabel) -> &'static str {
    match l {
        ExposureLabel::PrivateData => "private data",
        ExposureLabel::UntrustedContent => "untrusted content",
        ExposureLabel::ExfilVector => "exfiltration",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uninhabitable_state::UninhabitableState;
    use crate::{Operation, StateRisk, WeakeningGap};

    const ALL: [ExposureLabel; 3] = [
        ExposureLabel::PrivateData,
        ExposureLabel::UntrustedContent,
        ExposureLabel::ExfilVector,
    ];

    fn subsets() -> Vec<Vec<ExposureLabel>> {
        (0u8..8)
            .map(|mask| {
                ALL.iter()
                    .enumerate()
                    .filter(|(i, _)| mask & (1 << i) != 0)
                    .map(|(_, l)| *l)
                    .collect()
            })
            .collect()
    }

    fn summary(legs: Vec<ExposureLabel>, gated: Vec<Operation>) -> RiskSummary {
        RiskSummary {
            before: StateRisk::Safe,
            after: StateRisk::Safe,
            exposure_legs: legs,
            approval_gated: gated,
            gap: WeakeningGap::default(),
        }
    }

    /// THE property this module exists for. Every subset says something about
    /// what the combination *permits*, and no two subsets say the same thing —
    /// so the sentence carries the identity of the legs, not just their count.
    ///
    /// The count could never do this: there are three two-leg combinations and
    /// they permit three different things, one of which (private + exfil) is
    /// the exfiltration path and two of which are not.
    #[test]
    fn every_combination_permits_something_different() {
        let mut seen: Vec<&str> = subsets().iter().map(|s| mechanism(s)).collect();
        assert_eq!(seen.len(), 8, "there are eight subsets of three legs");
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        assert_eq!(
            before,
            seen.len(),
            "two combinations permit the same thing, so the sentence is only counting"
        );
    }

    /// The mechanism is about the join, not the parts. The two-leg combination
    /// that permits exfiltration must say so, and the two that do not must not
    /// — this is the distinction the count erased.
    #[test]
    fn only_the_combinations_with_a_path_out_say_data_leaves() {
        let leaves = |legs: &[ExposureLabel]| {
            let m = mechanism(legs);
            m.contains("can leave the sandbox") || m.contains("send it out of the sandbox")
        };
        assert!(leaves(&[
            ExposureLabel::PrivateData,
            ExposureLabel::ExfilVector
        ]));
        assert!(leaves(&ALL));
        assert!(!leaves(&[
            ExposureLabel::PrivateData,
            ExposureLabel::UntrustedContent
        ]));
        assert!(!leaves(&[
            ExposureLabel::UntrustedContent,
            ExposureLabel::ExfilVector
        ]));
        assert!(!leaves(&[ExposureLabel::PrivateData]));
        assert!(!leaves(&[]));
    }

    /// The bug this replaces. A grant with obligations but fewer than three
    /// legs used to be told, flatly, that no approval would be asked for.
    #[test]
    fn a_gated_operation_is_reported_however_many_legs_there_are() {
        for legs in subsets() {
            let n = legs.len();
            let line = risk_line(&summary(legs, vec![Operation::GitPush]));
            assert!(
                line.contains("asks for approval before git_push"),
                "{n} legs and an obligation, yet: {line}"
            );
            assert!(
                !line.contains("no approval prompts expected"),
                "{n} legs: promised no prompts while holding an obligation: {line}"
            );
        }
    }

    /// Non-vacuity for the test above: with no obligation the line still says
    /// so, at every leg count, so the assertion is not passing because the
    /// clause is always present.
    #[test]
    fn an_ungated_grant_is_told_no_prompts_at_every_leg_count() {
        for legs in subsets() {
            let line = risk_line(&summary(legs, Vec::new()));
            assert!(line.contains("no approval prompts expected"), "{line}");
        }
    }

    /// The canonical combination is the one the constraint system already
    /// names. Reading `.name` here is the first time any renderer has: the
    /// field has carried "which combination is dangerous and what is it
    /// called" since it was introduced, unread.
    #[test]
    fn the_three_leg_line_describes_the_combination_the_nucleus_names() {
        let canonical = UninhabitableState::canonical();
        assert_eq!(canonical.risk_grade, StateRisk::Uninhabitable);
        assert_eq!(canonical.required_core_labels.len(), 3);
        let line = risk_line(&summary(ALL.to_vec(), vec![Operation::GitPush]));
        assert!(line.starts_with("all 3 exposure legs present"), "{line}");
        assert!(
            line.contains("read private data and send it out of the sandbox"),
            "the trifecta line must say what the trifecta permits: {line}"
        );
    }

    /// A line always names which legs are present, so a person can check the
    /// mechanism sentence against the grant rather than trusting it.
    #[test]
    fn every_line_names_the_legs_it_reasons_from() {
        for legs in subsets() {
            let line = risk_line(&summary(legs.clone(), Vec::new()));
            for l in &legs {
                assert!(line.contains(leg_name(*l)), "{line} omits {l:?}");
            }
        }
    }
}
