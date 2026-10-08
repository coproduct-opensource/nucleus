//! The isolation profile a pod asks to be held to (ADR 0013).
//!
//! A profile is a set of admission requirements that sit **above** the node's
//! ordinary admission. It never relaxes anything: every check a pod passes under
//! [`IsolationProfile::Standard`] it passes under every other profile too.
//!
//! # Where it is written, and why there
//!
//! The profile is the metadata label [`PROFILE_LABEL`], parsed here into a closed
//! enum at the boundary (ADR 0007 I-2) by the one decider, [`IsolationProfile::of`].
//! It is a label rather than a `PodSpecInner` field because the guest's
//! tool-proxy parses the pod spec with `deny_unknown_fields`: a new field would
//! make every eval-cell pod unparseable by the pinned guest release, while the
//! label map is already part of the spec every published guest reads. Labels
//! are IN the program identity whole (`identity::program_digest`), so two pods
//! that differ only in profile are different programs.
//!
//! # No default that grants (ADR 0007 B)
//!
//! - An **unknown** value is refused ([`UnknownProfile`]), never read as
//!   standard: a typo of `eval-cell` must not admit a pod under weaker rules
//!   than its author asked for (B-3).
//! - An **absent** label is [`IsolationProfile::Standard`]. That is not a grant:
//!   standard is the admission every pod already gets, and absence asks for
//!   nothing beyond it. The one place absence could shed a requirement — a child
//!   created by an eval-cell pod omitting the label — is refused by the node,
//!   which holds a child to its parent's profile (`nucleus-node`'s `eval_cell`).
//! - There is no `Default` impl (B-1); the decider states the absent case.

use crate::PodSpec;
use crate::tier2_artifacts::GuestUse;

/// The label a pod spec names its isolation profile in.
pub const PROFILE_LABEL: &str = "isolation.coproduct.one/profile";

/// The isolation profiles this build knows. Matched exhaustively everywhere a
/// profile decides something (ADR 0007 E-2), so a new profile does not compile
/// until each decider says what it requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IsolationProfile {
    /// The node's ordinary admission, unchanged.
    Standard,
    /// ADR 0013: a cell for running an agent assumed hostile, with guest root.
    /// Firecracker only; no egress that is not listed host by host; enforcing
    /// credential delivery; the VMM's seccomp verified; the jailer on; and the
    /// guest's workload Landlock and derived syscall filter required.
    EvalCell,
}

impl IsolationProfile {
    /// Every profile, for callers and tests that must cover all of them.
    pub const ALL: [IsolationProfile; 2] = [IsolationProfile::Standard, IsolationProfile::EvalCell];

    /// The spelling in [`PROFILE_LABEL`] and on the command line.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            IsolationProfile::Standard => "standard",
            IsolationProfile::EvalCell => "eval-cell",
        }
    }

    /// Parse a profile name. The names are derived from [`Self::name`], so the
    /// parser and the printer cannot disagree (ADR 0007 G-1).
    ///
    /// # Errors
    ///
    /// [`UnknownProfile`] for any other spelling, including an empty one.
    pub fn parse(value: &str) -> Result<Self, UnknownProfile> {
        Self::ALL
            .into_iter()
            .find(|profile| profile.name() == value)
            .ok_or_else(|| UnknownProfile {
                value: value.to_string(),
            })
    }

    /// The profile `spec` asks for: its [`PROFILE_LABEL`], or
    /// [`IsolationProfile::Standard`] when the label is absent. The one decider.
    ///
    /// # Errors
    ///
    /// [`UnknownProfile`] when the label is present and names no profile.
    pub fn of(spec: &PodSpec) -> Result<Self, UnknownProfile> {
        match spec.metadata.labels.get(PROFILE_LABEL) {
            None => Ok(IsolationProfile::Standard),
            Some(value) => Self::parse(value),
        }
    }

    /// Write this profile into `spec`'s labels, so the node decides it.
    pub fn label(self, spec: &mut PodSpec) {
        spec.metadata
            .labels
            .insert(PROFILE_LABEL.to_string(), self.name().to_string());
    }

    /// The guest uses this profile makes, for the guest-skew decider
    /// (`tier2_artifacts::guest_skew_for`): a capability the profile requires of
    /// the guest is a [`crate::tier2_artifacts::Demand::When`] row for one of
    /// these, so it is required here and stays optional for every other pod.
    #[must_use]
    pub const fn guest_uses(self) -> &'static [GuestUse] {
        match self {
            IsolationProfile::Standard => &[],
            IsolationProfile::EvalCell => &[GuestUse::EvalCell],
        }
    }
}

impl std::fmt::Display for IsolationProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// A profile name this build does not know. Refused, never read as standard.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "isolation profile `{value}` ({PROFILE_LABEL}) is not one this build knows (standard, \
     eval-cell). An unknown profile is refused rather than read as standard, so a misspelled \
     profile cannot admit a pod under weaker rules than its author asked for."
)]
pub struct UnknownProfile {
    /// The spelling that did not parse.
    pub value: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(labels: &[(&str, &str)]) -> PodSpec {
        let mut spec: PodSpec =
            serde_json::from_str(r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{}}"#)
                .expect("a minimal spec parses");
        for (k, v) in labels {
            spec.metadata.labels.insert((*k).into(), (*v).into());
        }
        spec
    }

    #[test]
    fn every_name_round_trips_and_nothing_else_parses() {
        for profile in IsolationProfile::ALL {
            assert_eq!(IsolationProfile::parse(profile.name()), Ok(profile));
        }
        for unknown in [
            "",
            "eval_cell",
            "Eval-Cell",
            "evalcell",
            "eval-cell ",
            "default",
        ] {
            assert_eq!(
                IsolationProfile::parse(unknown),
                Err(UnknownProfile {
                    value: unknown.to_string()
                }),
                "{unknown:?} must be refused, not read as a profile"
            );
        }
    }

    /// ADR 0007 B-3: an unknown value denies. An absent label is standard,
    /// which grants nothing a pod without the label did not already have.
    #[test]
    fn an_unknown_label_is_refused_and_an_absent_one_is_standard() {
        assert_eq!(
            IsolationProfile::of(&spec(&[])),
            Ok(IsolationProfile::Standard)
        );
        assert_eq!(
            IsolationProfile::of(&spec(&[(PROFILE_LABEL, "eval-cell")])),
            Ok(IsolationProfile::EvalCell)
        );
        let refused = IsolationProfile::of(&spec(&[(PROFILE_LABEL, "eval-cel")]))
            .expect_err("a misspelled profile is refused");
        assert!(refused.to_string().contains("eval-cel"), "{refused}");
    }

    #[test]
    fn labelling_a_spec_is_read_back_by_the_decider() {
        for profile in IsolationProfile::ALL {
            let mut s = spec(&[]);
            profile.label(&mut s);
            assert_eq!(IsolationProfile::of(&s), Ok(profile));
        }
    }
}
