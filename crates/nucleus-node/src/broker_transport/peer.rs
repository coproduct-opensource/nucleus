//! Who may connect to a pod's broker socket, decided by the kernel.
//!
//! # Why the two drivers differ
//!
//! On Firecracker the broker's peer is always the pod's VMM: it forwards the
//! guest's vsock connections, so the kernel's peer credentials name the VMM
//! and never the guest process behind it. What keeps every other host process
//! out is the socket's `0700` directory and its jailed owner
//! (`guest_socket::bind_guest_listener`), and what tells the mediating proxy
//! from the rest of the guest is the broker capability on every frame.
//!
//! A container pod has no VMM in between. Its broker socket sits in the pod
//! directory the node bind-mounts into exactly that container (#2906), so the
//! connecting process is the peer, and the kernel reports which one it is. The
//! only process that may ask the host to perform a call is the node's
//! tool-proxy, which is the container's entrypoint and so its init: PID 1 in
//! the container's pid namespace (the node creates it with `init: false`, so no
//! runtime shim takes that place). The container runtime reports that
//! process's host pid after start, and the listener admits that pid and nothing
//! else — the workload the proxy spawned, a `docker exec` into the container,
//! and every host process are refused before a byte of a frame is read.
//!
//! # Armed after start, waited for, never assumed
//!
//! The socket must exist before the container starts (the proxy may dial it as
//! soon as it serves), and the init's pid exists only after. So the rule is
//! created unarmed, and the launch path arms it once, by value
//! ([`ArmContainerInit::arm`], ADR 0007 C-4), with the pid the runtime reported.
//! A connection that arrives first waits for the arming, up to the connection
//! deadline; a rule whose arm was dropped unarmed refuses forever. Neither is
//! "no rule": an unarmed rule admits nobody (B-2).
//!
//! # What this does not establish
//!
//! A peer pid of 0 means the peer is not visible from the node's pid namespace
//! (a node that itself runs in a container without the host's pid namespace):
//! refused, by name, in the node's log. A node whose container runtime reports
//! pids from a namespace other than the node's (rootless runtimes with their
//! own pid namespace) refuses every peer the same way. Both fail closed.

use std::time::Duration;

/// Who may connect. No `Default` (ADR 0007 B-1): each launch path names its own.
#[derive(Clone)]
pub enum PeerRule {
    /// Firecracker: the peer is the pod's VMM; the socket's directory and owner
    /// are the gate, and the broker capability authenticates the proxy.
    VmmForwarded,
    /// A container pod: only the container's init process.
    ContainerInit(ContainerInit),
}

/// The receiving half of a container's init pid, set once by the launch path.
#[derive(Clone)]
pub struct ContainerInit {
    pid: tokio::sync::watch::Receiver<Option<u32>>,
}

/// How long after the listener is bound the launch path may name the
/// container's init. Docker's create, start and inspect take well under a
/// second; the bound is there so the right to choose who the broker admits
/// cannot be exercised long after the launch that minted it.
pub const ARM_WINDOW: Duration = Duration::from_secs(120);

/// The arming half: the one-shot right to name who this broker admits.
/// Consumed by [`Self::arm`]; dropping it unarmed, or arming it after
/// `not_after`, leaves the rule refusing every peer.
#[must_use = "an unarmed container broker admits nobody"]
pub struct ArmContainerInit {
    pid: tokio::sync::watch::Sender<Option<u32>>,
    /// Past this, the right is spent without effect.
    not_after: std::time::Instant,
}

impl ArmContainerInit {
    /// Admit the process the container runtime reported as this container's
    /// init, and only it, for the listener's whole life.
    ///
    /// # Errors
    /// [`PeerRefused::ArmExpired`] past `not_after`: the broker then admits
    /// nobody, and the launch that asked fails by name.
    pub fn arm(self, pid: u32) -> Result<(), PeerRefused> {
        if std::time::Instant::now() > self.not_after {
            return Err(PeerRefused::ArmExpired);
        }
        // Receivers keep the last value after the sender is dropped, so a
        // connection that checks after this returns still sees the pid.
        let _ = self.pid.send(Some(pid));
        Ok(())
    }
}

/// A container's peer rule, unarmed, and the one way to arm it, valid until
/// `not_after`.
pub fn container_init(not_after: std::time::Instant) -> (ArmContainerInit, ContainerInit) {
    let (tx, rx) = tokio::sync::watch::channel(None);
    (
        ArmContainerInit { pid: tx, not_after },
        ContainerInit { pid: rx },
    )
}

/// Why a peer was refused. Logged by the node; the peer itself is answered with
/// the same coarse refusal an unauthenticated frame gets.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PeerRefused {
    /// The launch path never reported the container's init.
    #[error("the container's init process was never reported, so no peer can be admitted")]
    NotArmed,
    /// The launch path named the container's init after the arming window.
    #[error(
        "the container's init process was reported after the arming window closed, so no peer \
         will be admitted"
    )]
    ArmExpired,
    /// The kernel could not name the peer, or named it as pid 0: it is outside
    /// the node's pid namespace.
    #[error(
        "the peer's pid is not visible from the node's pid namespace; a node that runs in a \
         container needs the host's pid namespace to serve a container pod's broker"
    )]
    Invisible,
    /// A process other than the container's init.
    #[error(
        "peer pid {observed} is not the container's init (pid {expected}): only the pod's \
         tool-proxy may ask the host to perform a call"
    )]
    NotTheInit { expected: u32, observed: u32 },
    /// The kernel's peer credentials could not be read.
    #[error("the peer's credentials could not be read: {0}")]
    Unreadable(String),
}

/// The decision, over what the kernel reported. Pure, so it is tested without
/// a container.
pub fn admit_pid(expected: u32, observed: Option<i32>) -> Result<(), PeerRefused> {
    match observed.and_then(|pid| u32::try_from(pid).ok()) {
        None | Some(0) => Err(PeerRefused::Invisible),
        Some(observed) if observed == expected => Ok(()),
        Some(observed) => Err(PeerRefused::NotTheInit { expected, observed }),
    }
}

impl PeerRule {
    /// Admit or refuse an accepted connection, waiting at most `deadline` for an
    /// unarmed container rule to be armed.
    pub async fn admit(
        &self,
        stream: &tokio::net::UnixStream,
        deadline: Duration,
    ) -> Result<(), PeerRefused> {
        match self {
            PeerRule::VmmForwarded => Ok(()),
            PeerRule::ContainerInit(init) => {
                let mut pid = init.pid.clone();
                let armed = tokio::time::timeout(deadline, pid.wait_for(Option::is_some)).await;
                let expected = match armed {
                    Ok(Ok(value)) => (*value).ok_or(PeerRefused::NotArmed)?,
                    Ok(Err(_)) | Err(_) => return Err(PeerRefused::NotArmed),
                };
                let observed = stream
                    .peer_cred()
                    .map_err(|e| PeerRefused::Unreadable(e.to_string()))?
                    .pid();
                admit_pid(expected, observed)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The decision table, over every shape the kernel can report.
    #[test]
    fn only_the_reported_init_is_admitted() {
        assert_eq!(admit_pid(4242, Some(4242)), Ok(()));
        assert_eq!(
            admit_pid(4242, Some(4243)),
            Err(PeerRefused::NotTheInit {
                expected: 4242,
                observed: 4243
            })
        );
        for invisible in [None, Some(0), Some(-1)] {
            assert_eq!(
                admit_pid(4242, invisible),
                Err(PeerRefused::Invisible),
                "{invisible:?}"
            );
        }
    }

    fn pair() -> (tokio::net::UnixStream, tokio::net::UnixStream) {
        tokio::net::UnixStream::pair().expect("socketpair")
    }

    fn fresh() -> (ArmContainerInit, ContainerInit) {
        container_init(std::time::Instant::now() + ARM_WINDOW)
    }

    fn own_pid() -> u32 {
        std::process::id()
    }

    /// A real socket: the kernel names this test process as the peer, so a rule
    /// armed with our pid admits it and one armed with any other refuses it.
    #[tokio::test]
    async fn the_kernel_names_the_peer() {
        let (served, _peer) = pair();
        let (arm, init) = fresh();
        arm.arm(own_pid()).expect("armed in time");
        let rule = PeerRule::ContainerInit(init);
        assert_eq!(rule.admit(&served, Duration::from_secs(1)).await, Ok(()));

        let (arm, init) = fresh();
        let other = own_pid().wrapping_add(1).max(2);
        arm.arm(other).expect("armed in time");
        assert_eq!(
            PeerRule::ContainerInit(init)
                .admit(&served, Duration::from_secs(1))
                .await,
            Err(PeerRefused::NotTheInit {
                expected: other,
                observed: own_pid()
            })
        );
    }

    /// Unarmed is not "no rule": a dropped arm refuses, and a rule nobody arms
    /// in time refuses at the deadline rather than admitting.
    #[tokio::test]
    async fn an_unarmed_rule_admits_nobody() {
        let (served, _peer) = pair();
        let (arm, init) = fresh();
        drop(arm);
        assert_eq!(
            PeerRule::ContainerInit(init)
                .admit(&served, Duration::from_secs(1))
                .await,
            Err(PeerRefused::NotArmed)
        );

        let (_kept, init) = fresh();
        assert_eq!(
            PeerRule::ContainerInit(init)
                .admit(&served, Duration::from_millis(50))
                .await,
            Err(PeerRefused::NotArmed)
        );
    }

    /// A connection that arrives before the launch path arms the rule waits for
    /// it rather than being refused for being early.
    #[tokio::test]
    async fn an_early_peer_waits_for_the_arming() {
        let (served, _peer) = pair();
        let (arm, init) = fresh();
        let rule = PeerRule::ContainerInit(init);
        let admit = tokio::spawn(async move { rule.admit(&served, Duration::from_secs(5)).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        arm.arm(own_pid()).expect("armed in time");
        assert_eq!(admit.await.expect("join"), Ok(()));
    }

    /// The right to name the init expires: armed after its window, it arms
    /// nothing, says so, and the rule refuses even the pid it was given.
    #[tokio::test]
    async fn an_arm_used_after_its_window_admits_nobody() {
        let (served, _peer) = pair();
        let past = std::time::Instant::now()
            .checked_sub(Duration::from_secs(1))
            .expect("a second ago");
        let (arm, init) = container_init(past);
        assert_eq!(arm.arm(own_pid()), Err(PeerRefused::ArmExpired));
        assert_eq!(
            PeerRule::ContainerInit(init)
                .admit(&served, Duration::from_secs(1))
                .await,
            Err(PeerRefused::NotArmed)
        );
    }
}
