//! Broker rollout is explicit: disabled, listen with legacy spec delivery, or
//! enforcing with credential-free host spec delivery. Firecracker enforcement
//! requires the workload API, host-side credential sources, the broker client in
//! the proxy, and guest-init honoring required host-spec selection. Readiness
//! checks refuse when those pieces are unavailable; listen mode preserves its
//! prior delivery behavior.

#![cfg_attr(not(test), allow(dead_code))]

/// Other drivers do not prepare the credential-free workload API delivery path.
/// Refuse the requested mode rather than silently launch with legacy credentials.
pub(crate) fn require_supported_driver(
    enforcing: bool,
    driver: &crate::driver::DriverKind,
) -> Result<(), crate::ApiError> {
    if enforcing && !matches!(driver, crate::driver::DriverKind::Firecracker) {
        return Err(crate::ApiError::Driver(
            "--broker-enforcing requires the Firecracker host-spec delivery path".into(),
        ));
    }
    Ok(())
}

/// What a node should do about the credential broker for a given pod.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerRollout {
    /// Do not create the socket. Indistinguishable from before this work.
    Disabled,
    /// Create the socket and answer requests, but keep delivering credentials
    /// the existing way.
    ListenOnly,
    /// Serve the socket AND stop putting credential values in the guest spec.
    ///
    /// Explicitly enabled and checked by the launch preparation path.
    Enforcing,
}

impl BrokerRollout {
    /// Whether the broker socket should be created for this pod.
    pub fn serves_socket(self) -> bool {
        matches!(self, BrokerRollout::ListenOnly | BrokerRollout::Enforcing)
    }

    /// Whether credential values should be withheld from the guest spec.
    ///
    /// Separate from [`serves_socket`](Self::serves_socket) on purpose: the
    /// delivery change must not happen while merely turning the listener on.
    pub fn withholds_credentials(self) -> bool {
        matches!(self, BrokerRollout::Enforcing)
    }
}

/// How a guest can reach the broker, if it can at all.
///
/// # Why this is not just "has vsock"
///
/// The first version keyed on vsock, because the Firecracker path was the only
/// one being built for. That made the container driver structurally unable to
/// have a broker — and the container driver is the one that **actually carries
/// the credential exposure**, injecting values straight into the process
/// environment. Keying on vsock encoded "the driver we designed for" as though
/// it were "the driver that can be served".
///
/// A container has no vsock. It does have a filesystem, and `spawn_container_pod`
/// already bind-mounts the pod directory into it. A Unix socket there is reachable
/// with **no new mount**, which matters: bind-mounting more surface into an agent
/// sandbox is how sandbox escapes happen, and the best-known example is mounting
/// the Docker daemon socket, which hands the guest the whole host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerTransport {
    /// No way to reach a broker. The rollout is forced to
    /// [`BrokerRollout::Disabled`].
    None,
    /// A guest-initiated vsock connection (Firecracker).
    Vsock,
    /// A Unix socket in the pod directory, already visible to the guest
    /// (container).
    ///
    /// # Admitted by this predicate, not yet reachable in practice
    ///
    /// The container spawn path does not construct one, and the reason is not
    /// missing wiring. `broker_launch::broker_identity` refuses to serve a pod
    /// with no host-established identity, and **the container driver registers
    /// none** — there is no `identity_manager` call on that path at all.
    ///
    /// Giving containers an identity is not a line of glue either. On the
    /// Firecracker path an identity comes with an attested SVID and a netns that
    /// default-denies egress; a container has neither, so the identity would
    /// assert something the driver cannot back. That is the same defect as
    /// letting the guest name itself, one level up: an identity nobody
    /// established.
    ///
    /// So this variant records that the *transport* is not the obstacle, which
    /// is worth knowing — the obstacle is that the container driver has no
    /// story for workload identity, and inventing one to unblock a socket would
    /// be the claim outrunning the wiring again.
    PodDirSocket,
}

impl BrokerTransport {
    /// Whether a guest can reach a broker at all over this transport.
    pub fn is_reachable(self) -> bool {
        !matches!(self, BrokerTransport::None)
    }
}

/// Decide the rollout state for a pod.
///
/// The transport matters because without one there is no socket to create,
/// whatever the operator asked for. Failing closed to
/// [`BrokerRollout::Disabled`] there is right: a node that thinks it is
/// enforcing while no socket exists would strip credentials with nothing to
/// replace them.
pub fn decide_rollout(
    requested_enforcing: bool,
    requested_listen: bool,
    transport: BrokerTransport,
) -> BrokerRollout {
    if !transport.is_reachable() {
        return BrokerRollout::Disabled;
    }
    if requested_enforcing {
        return BrokerRollout::Enforcing;
    }
    if requested_listen {
        return BrokerRollout::ListenOnly;
    }
    BrokerRollout::Disabled
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_drivers_cannot_silently_downgrade_enforcement() {
        use crate::driver::DriverKind;
        assert!(require_supported_driver(true, &DriverKind::Firecracker).is_ok());
        for driver in [DriverKind::Container, DriverKind::AppleVz] {
            assert!(require_supported_driver(true, &driver).is_err());
            assert!(require_supported_driver(false, &driver).is_ok());
        }
        #[cfg(feature = "local-driver")]
        assert!(require_supported_driver(true, &DriverKind::Local).is_err());
    }

    /// Default is off. A node that has not asked for the broker behaves exactly
    /// as it did before this work.
    #[test]
    fn the_default_is_disabled() {
        assert_eq!(
            decide_rollout(false, false, BrokerTransport::Vsock),
            BrokerRollout::Disabled
        );
        assert!(!BrokerRollout::Disabled.serves_socket());
        assert!(!BrokerRollout::Disabled.withholds_credentials());
    }

    /// **The safety property of this whole module.** Turning the listener on
    /// must NOT withhold credentials: legacy clients retain their delivery mode.
    #[test]
    fn listening_does_not_withhold_credentials() {
        let r = decide_rollout(false, true, BrokerTransport::Vsock);
        assert_eq!(r, BrokerRollout::ListenOnly);
        assert!(r.serves_socket(), "the socket should exist");
        assert!(
            !r.withholds_credentials(),
            "listening must not change how credentials are delivered — the guest \
             cannot ask for them yet, so withholding only breaks the pod"
        );
    }

    /// Enforcing is reachable, but only by asking for it by name.
    #[test]
    fn enforcing_requires_asking_for_it_explicitly() {
        let r = decide_rollout(true, false, BrokerTransport::Vsock);
        assert_eq!(r, BrokerRollout::Enforcing);
        assert!(r.serves_socket() && r.withholds_credentials());
    }

    /// **Every transport that can reach a broker serves one.** The point of
    /// naming transports rather than asking "has vsock" is that a container can
    /// be served too — and it is the driver that actually carries the credential
    /// exposure, so excluding it excluded the case that matters most.
    #[test]
    fn a_container_transport_is_served_like_a_vsock_one() {
        for transport in [BrokerTransport::Vsock, BrokerTransport::PodDirSocket] {
            assert_eq!(
                decide_rollout(false, true, transport),
                BrokerRollout::ListenOnly,
                "{transport:?} can reach a broker, so it should be served"
            );
            assert_eq!(
                decide_rollout(true, false, transport),
                BrokerRollout::Enforcing,
                "{transport:?} can reach a broker, so it can enforce"
            );
        }
    }

    /// The transport set and the reachability predicate must not drift apart: a
    /// new variant that nobody classified would otherwise default to whatever
    /// `is_reachable` happens to say.
    #[test]
    fn only_the_none_transport_is_unreachable() {
        for transport in [
            BrokerTransport::None,
            BrokerTransport::Vsock,
            BrokerTransport::PodDirSocket,
        ] {
            let served = decide_rollout(false, true, transport).serves_socket();
            assert_eq!(
                served,
                transport.is_reachable(),
                "{transport:?} disagrees with its own reachability"
            );
        }
    }

    /// **Fail closed without a transport.** A node with no transport has no socket
    /// to create, so "enforcing" there would strip credentials with nothing to
    /// replace them — worse than not enabling it at all.
    #[test]
    fn without_vsock_even_enforcing_falls_back_to_disabled() {
        assert_eq!(
            decide_rollout(true, true, BrokerTransport::None),
            BrokerRollout::Disabled,
            "enforcing without a transport would withhold credentials and offer \
             no way to obtain them"
        );
    }

    /// Withholding is a strict subset of serving: nothing may withhold without
    /// also serving, or a pod loses its credentials with no broker to ask.
    #[test]
    fn nothing_withholds_without_also_serving() {
        for r in [
            BrokerRollout::Disabled,
            BrokerRollout::ListenOnly,
            BrokerRollout::Enforcing,
        ] {
            if r.withholds_credentials() {
                assert!(
                    r.serves_socket(),
                    "{r:?} withholds credentials without serving a socket"
                );
            }
        }
    }
}
