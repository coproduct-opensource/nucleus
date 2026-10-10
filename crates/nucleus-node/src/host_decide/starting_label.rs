//! The host's label for a pod before its guest says anything (ADR 0014 §3, S3).
//!
//! The host's [`HostTaint`] used to start clean and learn about a guest-local
//! read only from the guest's `Observe` frames. A guest that stays silent was
//! therefore never held: its silence read as "nothing untrusted entered". Under
//! the adversary of ADR 0013 (guest root), the guest's silence is not evidence
//! (A-2), so the label now starts at the join of what the HOST put into the cell
//! at admission. [`StartingLabel::of`] is the one decider of that.
//!
//! # What lowers it
//!
//! Nothing the caller writes. An eval cell starts untrusted whatever its spec
//! says, because a provenance claim is written by the caller. For a standard pod,
//! §3 lets a provenance claim lower the starting label only when the host has
//! verified it: a digest the node computed over the disk, signed by a key in the
//! node's trust set. This node has no such trust set and a spec has no claim
//! field, so no claim is ever verified, and none lowers anything. That is the
//! strong reading. It is not a "verify later" grace: when the verifier exists,
//! it is a new [`StartingLabel`] arm that this exhaustive match has to admit.

use nucleus_decision_protocol::kernel::HostTaint;
use nucleus_decision_protocol::{IFCLabel, LabelRaise};
use nucleus_spec::isolation_profile::IsolationProfile;

use crate::workspace_scan::Source;

/// Why a pod starts untrusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Untrusted {
    /// An eval cell: untrusted whatever its spec says (the accepted strongest
    /// option, ADR 0014 §3).
    EvalCell,
    /// A standard pod into which the host put caller-supplied content, named by
    /// the spec field that carries it (`workspace_scan::sources`).
    Workspace { field: &'static str },
    /// A pod restored from disk. Its starting label was not persisted, and
    /// "could not look" is not "clean" (A-2). Such a pod has no policy history
    /// either (`PolicyHistory::UnavailableAfterRestart`), so no decision is
    /// taken under this label today; it exists so that none ever could be under
    /// a clean one.
    Restored,
}

/// The host's label for a pod at admission.
///
/// No `Default` (ADR 0007 B-1): a starting label is decided by
/// [`StartingLabel::of`], never assumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartingLabel {
    /// Nothing caller-supplied entered: no caller disk on a microVM, and not an
    /// eval cell.
    Clean,
    /// Something did, or the pod is an eval cell.
    Untrusted(Untrusted),
}

impl StartingLabel {
    /// The one decider. `sources` is `workspace_scan::sources` for the pod's spec
    /// on the node's driver: every host path whose contents enter the pod.
    pub(crate) fn of(profile: IsolationProfile, sources: &[Source]) -> Self {
        match profile {
            IsolationProfile::EvalCell => StartingLabel::Untrusted(Untrusted::EvalCell),
            IsolationProfile::Standard => match sources.first() {
                Some(source) => StartingLabel::Untrusted(Untrusted::Workspace {
                    field: source.field,
                }),
                None => StartingLabel::Clean,
            },
        }
    }

    /// The host's taint at the moment the pod's policy history begins.
    ///
    /// Untrusted input takes the lattice point adversarial content already has
    /// (public, adversarial integrity, no authority): the one web content, an
    /// upstream tool result and a sponsored offer share
    /// (`nucleus_ifc_kernel::flow::intrinsic_label`). No new lattice point is
    /// invented, so nothing proved about the lattice has to be re-proved.
    pub(crate) fn taint(self, now: u64) -> HostTaint {
        let mut taint = HostTaint::clean();
        match self {
            StartingLabel::Clean => {}
            StartingLabel::Untrusted(
                Untrusted::EvalCell | Untrusted::Workspace { .. } | Untrusted::Restored,
            ) => taint.raise(LabelRaise::new(IFCLabel::web_content(now))),
        }
        taint
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::DriverKind;
    use portcullis::exposure_core::EgressAggregates;

    fn spec(json: serde_json::Value) -> nucleus_spec::PodSpec {
        serde_json::from_value(json).expect("spec")
    }

    fn bare() -> nucleus_spec::PodSpec {
        spec(serde_json::json!({"apiVersion":"nucleus/v1","kind":"Pod","spec":{}}))
    }

    fn with_scratch() -> nucleus_spec::PodSpec {
        spec(
            serde_json::json!({"apiVersion":"nucleus/v1","kind":"Pod","spec":{
                "image": {"kernel_path": "/k", "rootfs_path": "/r", "scratch_path": "/caller/scratch.ext4"}
            }}),
        )
    }

    fn of(profile: IsolationProfile, s: &nucleus_spec::PodSpec, d: &DriverKind) -> StartingLabel {
        StartingLabel::of(profile, &crate::workspace_scan::sources(s, d))
    }

    /// An eval cell is untrusted whatever it carries, even with nothing at all:
    /// no claim and no empty workspace lowers it.
    #[test]
    fn an_eval_cell_starts_untrusted_whatever_its_spec_says() {
        for s in [bare(), with_scratch()] {
            let label = of(IsolationProfile::EvalCell, &s, &DriverKind::Firecracker);
            assert_eq!(label, StartingLabel::Untrusted(Untrusted::EvalCell));
            assert!(label.taint(0).is_tainted());
        }
    }

    /// A standard microVM pod is untrusted exactly when the caller put a disk
    /// in it; with none, the node made the disk and nothing entered.
    #[test]
    fn a_standard_pod_is_untrusted_when_caller_content_enters() {
        let label = of(
            IsolationProfile::Standard,
            &with_scratch(),
            &DriverKind::Firecracker,
        );
        assert_eq!(
            label,
            StartingLabel::Untrusted(Untrusted::Workspace {
                field: "image.scratch_path"
            })
        );
        assert!(label.taint(0).is_tainted());

        let clean = of(
            IsolationProfile::Standard,
            &bare(),
            &DriverKind::Firecracker,
        );
        assert_eq!(clean, StartingLabel::Clean);
        assert!(!clean.taint(0).is_tainted());

        // A container shares the caller's `work_dir`: it always enters.
        let container = of(IsolationProfile::Standard, &bare(), &DriverKind::Container);
        assert_eq!(
            container,
            StartingLabel::Untrusted(Untrusted::Workspace { field: "work_dir" })
        );
    }

    /// A restored pod is never clean.
    #[test]
    fn a_restored_pod_is_not_clean() {
        assert!(
            StartingLabel::Untrusted(Untrusted::Restored)
                .taint(0)
                .is_tainted()
        );
    }
}
