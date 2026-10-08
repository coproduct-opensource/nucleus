//! `nucleus run --isolation-profile` (ADR 0013): what the CLI decides, before
//! anything starts, about a run under an isolation profile.
//!
//! The node is the decider for a pod (`nucleus-node`'s `eval_cell`): the CLI
//! only writes the profile into the spec it sends. Two things the node never
//! sees are decided here: a host tier (`run --local`, `run --hook`), which has
//! no node, and the guest release the run asserts (`--guest-release`), which
//! the node cannot read off a rootfs.

use anyhow::{Result, bail};
use nucleus_spec::PodSpec;
use nucleus_spec::isolation_profile::IsolationProfile;
use nucleus_spec::tier2_artifacts::{self, GuestSkew};

use super::pod_egress::GUEST_FROM_THIS_TREE;

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
/// `guest` is `--guest-release`: `None` for the pinned release `setup`
/// installs, [`GUEST_FROM_THIS_TREE`] for a guest built from this checkout.
pub(super) fn refuse_guest_skew(profile: IsolationProfile, guest: Option<&str>) -> Result<()> {
    let (release, which) = match guest {
        None => (tier2_artifacts::GUEST_RELEASE, "the pinned guest release"),
        Some(GUEST_FROM_THIS_TREE) => return Ok(()),
        Some(release) => (release, "guest release"),
    };
    match tier2_artifacts::guest_skew_for(release, profile.guest_uses()) {
        Ok(()) => Ok(()),
        Err(skew) => {
            let cause = match &skew {
                GuestSkew::Lacks { missing, .. } => {
                    let names: Vec<String> = missing.iter().map(|c| format!("{c:?}")).collect();
                    format!("{which} does not ship {}", names.join(", "))
                }
                GuestSkew::Unorderable { .. } => format!("{which} cannot be checked"),
            };
            bail!("--isolation-profile {profile}: {cause}; {skew}")
        }
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
    /// naming the row; a standard run is not, and the pin serves both.
    #[test]
    fn an_eval_cell_on_a_guest_without_landlock_or_the_derived_filter_is_refused() {
        for (release, lacks) in [
            ("2.5.0", "WorkloadLandlock, WorkloadSyscallPolicy"),
            ("2.6.0", "WorkloadSyscallPolicy"),
        ] {
            let msg = refuse_guest_skew(IsolationProfile::EvalCell, Some(release))
                .expect_err("the guest lacks a row an eval cell requires")
                .to_string();
            assert!(msg.contains(lacks), "{release}: {msg}");
            refuse_guest_skew(IsolationProfile::Standard, Some(release))
                .expect("a standard run makes no eval-cell use of the guest");
        }
        for profile in IsolationProfile::ALL {
            refuse_guest_skew(profile, None).expect("the pinned release serves every profile");
            refuse_guest_skew(profile, Some(GUEST_FROM_THIS_TREE)).expect("this tree's guest");
        }
        assert!(refuse_guest_skew(IsolationProfile::EvalCell, Some("main")).is_err());
    }

    #[test]
    fn only_an_eval_cell_is_labelled() {
        let base: PodSpec =
            serde_json::from_str(r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{}}"#)
                .expect("parses");
        let mut standard = base.clone();
        label(IsolationProfile::Standard, &mut standard);
        assert!(standard.metadata.labels.is_empty());
        let mut eval = base;
        label(IsolationProfile::EvalCell, &mut eval);
        assert_eq!(IsolationProfile::of(&eval), Ok(IsolationProfile::EvalCell));
    }
}
