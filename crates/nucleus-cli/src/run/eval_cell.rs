//! `nucleus run --isolation-profile` (ADR 0013): what the CLI decides, before
//! anything starts, about a run under an isolation profile.
//!
//! The node is the decider for a pod (`nucleus-node`'s `eval_cell`): the CLI
//! only writes the profile into the spec it sends. Two things the node never
//! sees are decided here: a host tier (`run --local`, `run --hook`), which has
//! no node, and whether the guest the run boots (as the node reports it, or as
//! `--guest-release` states it) carries what the profile requires.

use anyhow::{Result, bail};
use nucleus_spec::PodSpec;
use nucleus_spec::isolation_profile::IsolationProfile;

use super::guest_release::GuestBasis;

/// `clap`'s parser for `--isolation-profile`: the one decider's names.
pub(super) fn parse(value: &str) -> Result<IsolationProfile, String> {
    IsolationProfile::parse(value).map_err(|e| e.to_string())
}

/// Refuse a profile above standard on a host tier, naming the tier. A host
/// tier runs the agent as a process on this machine; there is no VM to hold.
pub(super) fn refuse_host_tier(profile: IsolationProfile, command: &str) -> Result<()> {
    match profile {
        IsolationProfile::Standard => Ok(()),
        IsolationProfile::EvalCell => bail!(
            "--isolation-profile eval-cell is refused on the `{command}` tier: it runs the agent \
             on this host with no microVM, and an eval cell runs only on a Firecracker node \
             (ADR 0013). Run it in a pod: drop --local/--hook and point --node-url at a \
             Firecracker node."
        ),
    }
}

/// Refuse a guest release that lacks a capability the profile requires of it,
/// by the one guest-skew decider and the profile's own uses.
///
/// `guest` is the guest the run boots, as the node reports it or as
/// `--guest-release` states it (`guest_release::reconcile`).
pub(super) fn refuse_guest_skew(profile: IsolationProfile, guest: &GuestBasis) -> Result<()> {
    match guest.skew_for(profile.guest_uses()) {
        Ok(()) => Ok(()),
        Err(refused) => bail!("--isolation-profile {profile}: {refused}"),
    }
}

/// Write the profile into the pod spec, for the node to decide. A standard run
/// writes nothing, so its spec (and program identity) is what it was before
/// the flag existed.
pub(super) fn label(profile: IsolationProfile, spec: &mut PodSpec) {
    match profile {
        IsolationProfile::Standard => {}
        IsolationProfile::EvalCell => profile.label(spec),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_spec::guest_release::{GuestOrigin, LOCAL_BUILD};

    /// A guest the run states with `--guest-release`.
    fn claimed(flag: &str) -> GuestBasis {
        GuestBasis::asserted(Some(flag)).expect("a flag was given")
    }

    /// The pinned release, as a node that boots it reports it.
    fn node_pin() -> GuestBasis {
        GuestBasis::Reported(GuestOrigin::Release {
            version: nucleus_spec::tier2_artifacts::GUEST_RELEASE.into(),
        })
    }

    #[test]
    fn an_eval_cell_is_refused_on_each_host_tier_by_name() {
        for command in ["run --local", "run --hook"] {
            let msg = refuse_host_tier(IsolationProfile::EvalCell, command)
                .expect_err("a host tier cannot hold an eval cell")
                .to_string();
            assert!(msg.contains(&format!("`{command}` tier")), "{msg}");
            refuse_host_tier(IsolationProfile::Standard, command)
                .expect("a standard run is unchanged");
        }
    }

    /// The release half of ADR 0013's guest requirement: 2.5.0 lacks both rows
    /// and 2.6.0 the derived filter, so an eval cell is refused on either,
    /// naming the row; a standard run is not, and the pin (as a node reports it)
    /// serves both.
    #[test]
    fn an_eval_cell_on_a_guest_without_landlock_or_the_derived_filter_is_refused() {
        for (release, lacks) in [
            ("2.5.0", "WorkloadLandlock, WorkloadSyscallPolicy"),
            ("2.6.0", "WorkloadSyscallPolicy"),
        ] {
            let msg = refuse_guest_skew(IsolationProfile::EvalCell, &claimed(release))
                .expect_err("the guest lacks a row an eval cell requires")
                .to_string();
            assert!(msg.contains(lacks), "{release}: {msg}");
            refuse_guest_skew(IsolationProfile::Standard, &claimed(release))
                .expect("a standard run makes no eval-cell use of the guest");
        }
        for profile in IsolationProfile::ALL {
            refuse_guest_skew(profile, &node_pin())
                .expect("the pinned release serves every profile");
            refuse_guest_skew(profile, &claimed(LOCAL_BUILD)).expect("this tree's guest");
        }
        assert!(refuse_guest_skew(IsolationProfile::EvalCell, &claimed("main")).is_err());
    }

    #[test]
    fn only_an_eval_cell_is_labelled() {
        let base: PodSpec =
            serde_json::from_str(r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{"policy":{"type":"profile","name":"default"}}}"#)
                .expect("parses");
        let mut standard = base.clone();
        label(IsolationProfile::Standard, &mut standard);
        assert!(standard.metadata.labels.is_empty());
        let mut eval = base;
        label(IsolationProfile::EvalCell, &mut eval);
        assert_eq!(IsolationProfile::of(&eval), Ok(IsolationProfile::EvalCell));
    }
}
