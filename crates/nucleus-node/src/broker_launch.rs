//! The decisions the pod launch path must make about the credential broker.
//!
//! Kept as pure functions rather than inlined into the spawn path, because the
//! spawn path needs a real VM to exercise and these are the parts that must be
//! right on a machine that has none.
//!
//! # Two forks, and why each is resolved the strict way
//!
//! **A pod with no workload identity gets no broker socket.** The broker binds
//! an identity to a listener, and that identity is supposed to be a fact the
//! host established. A pod that was never registered has no such fact, and
//! serving it anyway would mean inventing one — which is precisely the
//! sloppiness removed when `pod_identity` stopped coming off the wire. So the
//! answer is to not serve, and that composes with a gate already in place:
//! identity is only registered when the pod's egress is confined enough to hold
//! one, so **a pod with unconfined egress cannot obtain brokered credentials at
//! all**. The tradeoff is visible rather than hidden.
//!
//! **Under `Enforcing`, a listener that fails to start fails the launch.** This
//! is the one place the two rollout halves come apart at *runtime* rather than
//! at configuration time. `decide_rollout` already refuses to enforce without a
//! vsock, but a socket can also fail to bind for reasons no configuration check
//! can see: a stale path, a full filesystem, a permissions change. Enforcing
//! means credential values were withheld from the guest spec, so continuing
//! would launch a pod that has neither its credentials nor any way to ask for
//! them — and the failure would surface later as a confusing application error
//! rather than a launch refusal. Under `ListenOnly` nothing depends on the
//! socket yet, so a failure there is a warning.

// Not yet reachable from the spawn path itself in this change: the functions are
// consulted by `firecracker_spawn`, but the modules they gate (`cred_split`)
// only run under `Enforcing`, which is off by default.
#![cfg_attr(not(test), allow(dead_code))]

use crate::broker_rollout::BrokerRollout;
use nucleus_cred_broker::PodIdentity;

/// Why a launch refused to enforce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EnforcementRefused {
    /// The node does not write this pod's guest spec, so it cannot take
    /// anything out of it.
    #[error(
        "--broker-enforcing was requested, but this driver bakes the pod spec into the image at \
         build time, so the node has no guest spec to strip credentials from. Enforcing here \
         would serve a broker socket while the image still carried the credentials — a claim of \
         withholding that is not true. Use --broker-listen, or supply the spec at launch."
    )]
    NodeDoesNotWriteTheGuestSpec,
}

/// Refuse to *claim* enforcement the wiring cannot deliver.
///
/// # The failure mode this closes
///
/// `Enforcing` means two things: serve the socket, and withhold credential
/// values from the guest spec. On the Firecracker path the second is currently
/// impossible — `scripts/firecracker/build-rootfs.sh` copies the pod spec into
/// the rootfs at **image build time**, so the node never writes a guest spec and
/// [`crate::cred_split::split_credentials`] has nothing to run on.
///
/// An operator who passed `--broker-enforcing` there would get a broker socket
/// and a reasonable belief that credentials had been withheld, while the image
/// still carried them. That is worse than the feature being absent: it is a
/// security claim that outruns its wiring.
///
/// The available responses are to downgrade silently, to warn, or to refuse.
/// This refuses. A silent downgrade IS the failure mode — the operator asked for
/// enforcement, did not get it, and has no way to tell. A warning is a downgrade
/// that assumes someone is reading logs.
pub fn check_enforcement_is_honest(
    rollout: BrokerRollout,
    node_writes_the_guest_spec: bool,
) -> Result<BrokerRollout, EnforcementRefused> {
    if rollout.withholds_credentials() && !node_writes_the_guest_spec {
        return Err(EnforcementRefused::NodeDoesNotWriteTheGuestSpec);
    }
    Ok(rollout)
}

/// What the launch path should do when the broker socket cannot be created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartFailure {
    /// Fail the pod launch. The guest has been denied its credentials and has
    /// no way to ask for them, so it cannot do its job.
    AbortLaunch,
    /// Log and carry on. Nothing depends on the socket yet.
    ContinueDegraded,
}

/// Decide the identity to bind to a pod's broker listener.
///
/// `None` means **do not serve**, for either of two reasons that are one reason:
/// the rollout did not ask for a socket, or the pod has no established identity
/// to bind to one. Returning an `Option<PodIdentity>` rather than a bool and a
/// string keeps those inseparable — a caller cannot obtain a socket decision
/// without also obtaining the identity that socket will speak for.
pub fn broker_identity(
    rollout: BrokerRollout,
    registered: Option<&nucleus_identity::Identity>,
) -> Option<PodIdentity> {
    if !rollout.serves_socket() {
        return None;
    }
    // `observed_by_host` is accurate here: this identity was minted and
    // registered by the node, from pod metadata, before the guest ran.
    registered.map(|id| PodIdentity::observed_by_host(id.to_spiffe_uri()))
}

/// What to do when [`crate::broker_transport::prepare_socket`] fails.
///
/// Keyed on whether credentials were withheld, not on whether a socket was
/// wanted: the damage from a missing listener is entirely a function of whether
/// anything was taken away in exchange for it.
pub fn on_start_failure(rollout: BrokerRollout) -> StartFailure {
    if rollout.withholds_credentials() {
        StartFailure::AbortLaunch
    } else {
        StartFailure::ContinueDegraded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn an_identity() -> nucleus_identity::Identity {
        nucleus_identity::Identity::new("nucleus.local", "default", "pod-abc")
    }

    /// Disabled serves nothing, identity or not.
    #[test]
    fn a_disabled_rollout_serves_no_socket() {
        assert!(broker_identity(BrokerRollout::Disabled, Some(&an_identity())).is_none());
    }

    /// **The gate.** A pod the node never registered has no host-established
    /// identity, so there is nothing truthful to bind the listener to and it is
    /// not served. Since registration is itself gated on confined egress, a pod
    /// that kept public egress cannot reach brokered credentials.
    #[test]
    fn a_pod_without_an_identity_is_not_served_even_when_asked_for() {
        for rollout in [BrokerRollout::ListenOnly, BrokerRollout::Enforcing] {
            assert!(
                broker_identity(rollout, None).is_none(),
                "{rollout:?} served a socket for a pod with no established identity"
            );
        }
    }

    /// A registered pod is served, under the identity the node minted for it —
    /// not one derived from anything the guest supplied.
    #[test]
    fn a_registered_pod_is_served_under_the_identity_the_node_minted() {
        let id = an_identity();
        let bound = broker_identity(BrokerRollout::ListenOnly, Some(&id))
            .expect("a registered pod should be served");
        assert_eq!(bound.as_str(), id.to_spiffe_uri());
    }

    /// **Failing to bind is fatal exactly when credentials were withheld.**
    /// Enforcing means the guest spec was stripped, so a pod launched without a
    /// listener has neither its credentials nor a way to ask — a failure that
    /// would otherwise surface much later as an application error.
    #[test]
    fn a_failed_socket_aborts_the_launch_only_when_credentials_were_withheld() {
        assert_eq!(
            on_start_failure(BrokerRollout::Enforcing),
            StartFailure::AbortLaunch
        );
        assert_eq!(
            on_start_failure(BrokerRollout::ListenOnly),
            StartFailure::ContinueDegraded
        );
        assert_eq!(
            on_start_failure(BrokerRollout::Disabled),
            StartFailure::ContinueDegraded
        );
    }

    /// **A security claim may not outrun its wiring.** Asking to enforce where
    /// the node cannot strip the guest spec is refused, not quietly downgraded:
    /// the operator would otherwise believe credentials were withheld while the
    /// image still carried them.
    #[test]
    fn enforcement_is_refused_where_nothing_can_be_withheld() {
        assert_eq!(
            check_enforcement_is_honest(BrokerRollout::Enforcing, false),
            Err(EnforcementRefused::NodeDoesNotWriteTheGuestSpec)
        );
    }

    /// The refusal is specific to the claim, not to the broker. Serving a socket
    /// withholds nothing, so it is unaffected — otherwise this check would block
    /// the half that works in order to police the half that does not.
    #[test]
    fn listening_is_unaffected_by_the_enforcement_check() {
        for spec_written in [true, false] {
            assert_eq!(
                check_enforcement_is_honest(BrokerRollout::ListenOnly, spec_written),
                Ok(BrokerRollout::ListenOnly)
            );
            assert_eq!(
                check_enforcement_is_honest(BrokerRollout::Disabled, spec_written),
                Ok(BrokerRollout::Disabled)
            );
        }
        // And enforcing IS allowed where the node does write the spec.
        assert_eq!(
            check_enforcement_is_honest(BrokerRollout::Enforcing, true),
            Ok(BrokerRollout::Enforcing)
        );
    }

    /// Exactly the rollouts that withhold are the ones the check can refuse.
    /// Stated as a loop so a fourth variant cannot be added without deciding.
    #[test]
    fn only_withholding_rollouts_can_be_refused() {
        for rollout in [
            BrokerRollout::Disabled,
            BrokerRollout::ListenOnly,
            BrokerRollout::Enforcing,
        ] {
            assert_eq!(
                check_enforcement_is_honest(rollout, false).is_err(),
                rollout.withholds_credentials(),
                "{rollout:?} disagrees with its own withholding claim"
            );
        }
    }

    /// The two decisions must agree: anything that would abort on a start
    /// failure must have wanted a socket in the first place. A rollout that
    /// aborted the launch over a socket it never asked for would make the
    /// broker's failure mode worse than its absence.
    #[test]
    fn nothing_aborts_over_a_socket_it_never_wanted() {
        for rollout in [
            BrokerRollout::Disabled,
            BrokerRollout::ListenOnly,
            BrokerRollout::Enforcing,
        ] {
            if on_start_failure(rollout) == StartFailure::AbortLaunch {
                assert!(
                    broker_identity(rollout, Some(&an_identity())).is_some(),
                    "{rollout:?} aborts the launch over a socket it does not serve"
                );
            }
        }
    }
}
