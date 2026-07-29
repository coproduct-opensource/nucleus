//! When the credential broker is actually used, and why the order matters.
//!
//! # The ordering constraint
//!
//! The broker has two halves and they cannot land together:
//!
//! 1. **The host serves** — a listener the guest can reach, which decides and
//!    fetches. That exists.
//! 2. **The guest asks** — a client in the tool-proxy that sends an envelope
//!    instead of reading a credential from its spec. That does **not** exist.
//!
//! Until both exist, [`cred_split::split_credentials`](crate::cred_split) must
//! not run on the launch path. Stripping credential values from a guest whose
//! code still expects to read them does not make anything more secure; it makes
//! every pod fail. The exposure stays open for exactly as long as it takes the
//! guest to gain a way to ask.
//!
//! # Why the listener can land first anyway
//!
//! A listener that nobody connects to changes no behaviour. Landing it early
//! means the socket path, permissions, bounds and refusal semantics are in
//! production and exercised before anything depends on them — rather than
//! arriving in the same change that also flips how credentials are delivered.
//!
//! # Why it is still off by default
//!
//! Flags of this kind are runtime safety tools, not growth knobs. `Off` means a
//! node behaves exactly as it did; `On` means the socket exists and answers.
//! Neither setting yet changes how a credential reaches a workload, and this
//! module's tests say so explicitly so nobody reads the flag as "secretless mode".

// Not yet read by the launch path: the flag exists and is tested, but nothing
// consults it during pod spawn, because doing so is only useful once the guest
// has a client. Deliberately landed ahead of that so the DEFAULT-OFF decision
// is reviewable on its own rather than buried in the change that flips
// credential delivery. CI denies warnings; this states the gap rather than
// hiding it.
#![cfg_attr(not(test), allow(dead_code))]

/// What a node should do about the credential broker for a given pod.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerRollout {
    /// Do not create the socket. Indistinguishable from before this work.
    Disabled,
    /// Create the socket and answer requests, but keep delivering credentials
    /// the existing way — because the guest cannot ask yet.
    ListenOnly,
    /// Serve the socket AND stop putting credential values in the guest spec.
    ///
    /// Only correct once the guest has a client. Reachable today only by
    /// explicitly asking for it, so it can be exercised in a test environment.
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
    /// dangerous half is withholding, and it must be impossible to enable it by
    /// accident while merely turning the listener on.
    pub fn withholds_credentials(self) -> bool {
        matches!(self, BrokerRollout::Enforcing)
    }
}

/// Decide the rollout state for a pod.
///
/// `has_vsock` matters because the broker is reached over a guest-initiated
/// vsock connection; without one there is no socket to create, whatever the
/// operator asked for. Failing closed to [`BrokerRollout::Disabled`] there is
/// right: a node that thinks it is enforcing while no socket exists would strip
/// credentials with nothing to replace them.
pub fn decide_rollout(
    requested_enforcing: bool,
    requested_listen: bool,
    has_vsock: bool,
) -> BrokerRollout {
    if !has_vsock {
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

    /// Default is off. A node that has not asked for the broker behaves exactly
    /// as it did before this work.
    #[test]
    fn the_default_is_disabled() {
        assert_eq!(decide_rollout(false, false, true), BrokerRollout::Disabled);
        assert!(!BrokerRollout::Disabled.serves_socket());
        assert!(!BrokerRollout::Disabled.withholds_credentials());
    }

    /// **The safety property of this whole module.** Turning the listener on
    /// must NOT withhold credentials. The guest has no client yet, so a pod
    /// whose credentials were stripped would simply fail.
    #[test]
    fn listening_does_not_withhold_credentials() {
        let r = decide_rollout(false, true, true);
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
        let r = decide_rollout(true, false, true);
        assert_eq!(r, BrokerRollout::Enforcing);
        assert!(r.serves_socket() && r.withholds_credentials());
    }

    /// **Fail closed without a transport.** A node with no vsock has no socket
    /// to create, so "enforcing" there would strip credentials with nothing to
    /// replace them — worse than not enabling it at all.
    #[test]
    fn without_vsock_even_enforcing_falls_back_to_disabled() {
        assert_eq!(
            decide_rollout(true, true, false),
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
