//! Backend-agnostic enforcement gate for the isolation lattice.
//!
//! The permission/isolation *decision* is portable and (in the PCA fabric)
//! certificate-bearing; the *enforcement* is platform-specific. A Firecracker
//! host can enforce the full [`IsolationLattice`] (netns + iptables allowlist +
//! seccomp + read-only rootfs); an Apple `Virtualization.framework` host gives
//! you the VM boundary for free but exposes no host-side egress allowlist, no
//! namespaces tier, and no in-VM seccomp control — so it physically cannot
//! enforce some requested levels.
//!
//! This module makes that gap **explicit and safe** instead of silent. A
//! backend declares which levels it can enforce ([`BackendCapability`]); the
//! gate [`require_isolation`] maps a *requested* posture to the posture the
//! backend will actually *enforce*, **clamping up** to the nearest enforceable
//! level that is at least as strong (never weaker — the monotonicity the Lean
//! `CapabilityLattice` proofs care about), and recording both. A relying party
//! that asked for `Filtered` egress on Apple gets `Airgapped` (stronger) with a
//! visible record that the request was strengthened — it never gets a token
//! that *claims* `Filtered` while the platform silently allows the whole
//! internet through NAT.
//!
//! This module is pure and `ring`-free, so it compiles on WASM and into a zkVM
//! guest alongside the rest of the portable decision layer.

use crate::isolation::{FileIsolation, IsolationLattice, NetworkIsolation, ProcessIsolation};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// The floor of a backend that establishes nothing beyond the request: the
/// lattice's bottom, so joining it changes nothing.
const NO_FLOOR: IsolationLattice = IsolationLattice {
    process: ProcessIsolation::Shared,
    file: FileIsolation::Unrestricted,
    network: NetworkIsolation::Host,
};

/// What a concrete isolation backend can enforce, per lattice dimension.
///
/// Each slice lists exactly the levels the backend can honor *as specified*
/// (not by rounding up). A backend that omits a level can still satisfy a
/// request for it by enforcing a stronger level it *does* list — see
/// [`require_isolation`].
#[derive(Debug, Clone, Copy)]
pub struct BackendCapability {
    /// Human-readable backend name (for diagnostics / the enforced record).
    pub name: &'static str,
    /// Process-isolation levels this backend can enforce as specified.
    pub process: &'static [ProcessIsolation],
    /// File-isolation levels this backend can enforce as specified.
    pub file: &'static [FileIsolation],
    /// Network-isolation levels this backend can enforce as specified.
    pub network: &'static [NetworkIsolation],
    /// The posture this backend delivers **whatever is requested** — its floor.
    ///
    /// The slices above say which levels a request may be *held to*; this says
    /// what every pod on the backend gets regardless. They are different facts:
    /// a Firecracker pod that requests `process=shared` is clamped to `shared`
    /// (Firecracker can honour a request that weak), yet it still runs under its
    /// own kernel. Reporting the clamp alone listed microVM pods as
    /// `process=shared, file=unrestricted, network=host` (#3220).
    ///
    /// Joined into [`EnforcedIsolation::delivered`] by [`require_isolation`], the
    /// one place that reads it. Declare only what the backend's launch path
    /// establishes unconditionally — under-declaring costs an understated label,
    /// over-declaring is a claim nothing backs.
    pub delivers: IsolationLattice,
}

impl BackendCapability {
    /// Firecracker / Linux-KVM: enforces the **full** lattice — namespaces +
    /// iptables egress allowlist + seccomp + read-only/ephemeral rootfs.
    pub const FIRECRACKER: BackendCapability = BackendCapability {
        name: "firecracker",
        process: &[
            ProcessIsolation::Shared,
            ProcessIsolation::Namespaced,
            ProcessIsolation::MicroVM,
        ],
        file: &[
            FileIsolation::Unrestricted,
            FileIsolation::Sandboxed,
            FileIsolation::ReadOnly,
            FileIsolation::Ephemeral,
        ],
        network: &[
            NetworkIsolation::Host,
            NetworkIsolation::Namespaced,
            NetworkIsolation::Filtered,
            NetworkIsolation::Airgapped,
        ],
        // Every Firecracker pod gets all three, whatever it requests:
        // - process `MicroVM`: the workload runs under the guest's own kernel.
        // - file `ReadOnly`: the rootfs drive is always lowered `is_read_only`
        //   (`nucleus_node::firecracker_config`, "The rootfs drive is ALWAYS
        //   `is_read_only = true`"); only a scratch drive is writable, and no
        //   host path reaches the guest.
        // - network `Namespaced`: the guest has its own network stack, and a NIC
        //   is attached only with a host `NetPlan`, which is allocated only
        //   inside a per-pod netns (`NetnsPlan::decide`: a network policy without
        //   a netns is refused). With no NetPlan there is no NIC at all, which is
        //   stronger still; `Namespaced` is the level that holds in both cases.
        delivers: IsolationLattice {
            process: ProcessIsolation::MicroVM,
            file: FileIsolation::ReadOnly,
            network: NetworkIsolation::Namespaced,
        },
    };

    /// Apple `Virtualization.framework` (host-side enforcement). The VM
    /// boundary is strong, but Apple exposes:
    /// - **no namespaces tier** — process isolation is Shared or a full VM
    ///   (`MicroVM`), nothing in between;
    /// - **no in-VM cap-std `Sandboxed` guarantee** the host can attest — only
    ///   read-only / ephemeral VM disks;
    /// - **no host-side egress allowlist** — `vmnet` offers Host/NAT and
    ///   "no NIC" (`Airgapped`), but not `Filtered`.
    ///
    /// Requests for the absent levels are clamped **up** (e.g. `Filtered →
    /// Airgapped`, `Namespaced → MicroVM`, `Sandboxed → ReadOnly`). To recover
    /// the fine-grained levels on Apple, move enforcement into the guest init
    /// and expose a richer capability from there.
    pub const APPLE_VZ: BackendCapability = BackendCapability {
        name: "apple-vz",
        process: &[ProcessIsolation::Shared, ProcessIsolation::MicroVM],
        file: &[
            FileIsolation::Unrestricted,
            FileIsolation::ReadOnly,
            FileIsolation::Ephemeral,
        ],
        network: &[
            NetworkIsolation::Host,
            NetworkIsolation::Namespaced,
            NetworkIsolation::Airgapped,
        ],
        // No floor claimed: the boot driver is not implemented
        // (`nucleus_node::driver::spawn_vz_pod`), so there is no launch path to
        // cite. Declare one when there is.
        delivers: NO_FLOOR,
    };

    /// OCI container runtime. Declared at the minimum the node's container path
    /// can be shown to deliver — not at what a container could in principle do.
    ///
    /// Every level below is a citation, because over-declaring is the defect
    /// this constant closes (SECURITY_TODO #17: `--driver container` was clamped
    /// against [`BackendCapability::FIRECRACKER`] and labelled
    /// `backend=firecracker`). Under-declaring costs a refusal that names the
    /// dimension; over-declaring hands out a guarantee nothing delivers.
    ///
    /// - **process — `Namespaced`**: `spawn_container_pod`'s `HostConfig` sets
    ///   no `pid_mode`, so the runtime default private PID/mount/IPC namespace
    ///   applies. `MicroVM` is out of reach: there is no separate kernel.
    /// - **file — `Unrestricted` only**: the `HostConfig` sets no
    ///   `readonly_rootfs`, and `binds` mounts host directories `rw`. Nothing on
    ///   this path attests a cap-std `Sandboxed` root or an immutable rootfs.
    /// - **network — `Host` only**: `network_mode` comes from the
    ///   caller-settable `nucleus.io/network` label, so the node cannot assert a
    ///   namespace it does not control, and the driver refuses structured
    ///   `network` policy outright — it cannot express an egress allowlist.
    pub const CONTAINER: BackendCapability = BackendCapability {
        name: "container",
        process: &[ProcessIsolation::Shared, ProcessIsolation::Namespaced],
        file: &[FileIsolation::Unrestricted],
        network: &[NetworkIsolation::Host],
        // No floor claimed beyond the clamped request.
        delivers: NO_FLOOR,
    };

    /// Process-only execution: no VM, and no isolation the node establishes
    /// itself. The floor is the whole capability, which is the point — every
    /// stronger request is [`EnforcementError::Unenforceable`] and is refused
    /// rather than granted in name.
    ///
    /// `--driver local` is already refused in production builds
    /// (`nucleus_node::production_confinement`); this constant makes the posture
    /// it can back explicit rather than inherited from Firecracker's.
    pub const LOCAL: BackendCapability = BackendCapability {
        name: "local",
        process: &[ProcessIsolation::Shared],
        file: &[FileIsolation::Unrestricted],
        network: &[NetworkIsolation::Host],
        // Process-only execution establishes nothing of its own.
        delivers: NO_FLOOR,
    };

    /// Every backend this node can select, so a property that must hold "on
    /// every backend" cannot silently omit one. A new backend is a compile error
    /// here before it is a gap in the exhaustive tests below.
    pub const ALL: &'static [&'static BackendCapability] = &[
        &BackendCapability::FIRECRACKER,
        &BackendCapability::APPLE_VZ,
        &BackendCapability::CONTAINER,
        &BackendCapability::LOCAL,
    ];
}

/// The outcome of mapping a requested posture onto a backend: what was asked
/// for, and what will actually be enforced. By construction `enforced` is
/// at-least-as-strong as `requested` on **every** dimension.
///
/// **Construct only via [`require_isolation`]** — that is the sole path that
/// guarantees the `enforced ≥ requested` invariant. The type is intentionally
/// `Serialize`-only (no `Deserialize`): a deserialized value would bypass that
/// constructor and could assert `enforced` *weaker* than `requested`, defeating
/// the whole point. If wire round-trip is ever needed, add an owned wire type
/// with a validating `#[serde(try_from)]` rather than re-deriving `Deserialize`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct EnforcedIsolation {
    /// What the decision asked for.
    pub requested: IsolationLattice,
    /// What the backend will actually enforce (≥ `requested`, never weaker).
    /// The posture the pod's policy is held to: a strengthening here is
    /// written back into the policy.
    pub enforced: IsolationLattice,
    /// What the backend delivers: `enforced` joined with the backend's floor
    /// ([`BackendCapability::delivers`]). Always ≥ `enforced`. This is the
    /// posture to *report*; it does not tighten the policy, since a floor the
    /// backend provides anyway needs no policy to demand it.
    pub delivered: IsolationLattice,
    /// The backend that produced this enforcement.
    pub backend: &'static str,
}

impl EnforcedIsolation {
    /// `true` iff the backend enforces exactly what was requested (no clamp).
    pub fn is_faithful(&self) -> bool {
        self.enforced == self.requested
    }

    /// `true` iff the backend had to strengthen some dimension to enforce the
    /// request (e.g. Apple `Filtered → Airgapped`). Never a weakening.
    pub fn was_strengthened(&self) -> bool {
        !self.is_faithful()
    }

    /// The per-dimension strengthenings applied, for the audit record.
    pub fn strengthenings(&self) -> Vec<Strengthening> {
        let mut out = Vec::new();
        if self.enforced.process != self.requested.process {
            out.push(Strengthening {
                dimension: "process",
                requested: self.requested.process.as_str(),
                enforced: self.enforced.process.as_str(),
            });
        }
        if self.enforced.file != self.requested.file {
            out.push(Strengthening {
                dimension: "file",
                requested: self.requested.file.as_str(),
                enforced: self.enforced.file.as_str(),
            });
        }
        if self.enforced.network != self.requested.network {
            out.push(Strengthening {
                dimension: "network",
                requested: self.requested.network.as_str(),
                enforced: self.enforced.network.as_str(),
            });
        }
        out
    }
}

/// One dimension the backend strengthened to make the request enforceable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Strengthening {
    /// The lattice dimension ("process" | "file" | "network").
    pub dimension: &'static str,
    /// The level requested.
    pub requested: &'static str,
    /// The (stronger) level that will be enforced.
    pub enforced: &'static str,
}

/// Why a backend cannot enforce a requested posture even by strengthening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforcementError {
    /// No enforceable level on `dimension` is at least as strong as the
    /// request — the backend cannot satisfy it without weakening, so the gate
    /// fails closed rather than under-enforce.
    Unenforceable {
        /// The lattice dimension that could not be satisfied.
        dimension: &'static str,
        /// The requested level (string form).
        requested: &'static str,
        /// The backend that could not enforce it.
        backend: &'static str,
    },
}

impl std::fmt::Display for EnforcementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnforcementError::Unenforceable { dimension, requested, backend } => write!(
                f,
                "backend {backend} cannot enforce {dimension}={requested} (no level ≥ request is enforceable)"
            ),
        }
    }
}

impl std::error::Error for EnforcementError {}

/// The nearest enforceable level that is **at least as strong** as `requested`,
/// or `None` if the backend lists no level ≥ `requested`. Clamps up only —
/// returning a weaker level would silently under-enforce.
fn clamp_up<T: Ord + Copy>(requested: T, enforceable: &[T]) -> Option<T> {
    enforceable
        .iter()
        .copied()
        .filter(|&level| level >= requested)
        .min()
}

/// Map a requested [`IsolationLattice`] onto what `backend` will enforce.
///
/// Each dimension is clamped **up** to the nearest enforceable level ≥ the
/// request (so a faithful request stays put, and an unsupported one is
/// strengthened, never weakened). Fails closed with [`EnforcementError`] if a
/// dimension has no enforceable level ≥ the request.
///
/// The returned [`EnforcedIsolation`] satisfies `enforced.at_least(&requested)`
/// — the monotonicity the Lean lattice proofs assume — and records exactly what
/// was strengthened so the audit trail never overstates the request.
pub fn require_isolation(
    requested: IsolationLattice,
    backend: &BackendCapability,
) -> Result<EnforcedIsolation, EnforcementError> {
    let process =
        clamp_up(requested.process, backend.process).ok_or(EnforcementError::Unenforceable {
            dimension: "process",
            requested: requested.process.as_str(),
            backend: backend.name,
        })?;
    let file = clamp_up(requested.file, backend.file).ok_or(EnforcementError::Unenforceable {
        dimension: "file",
        requested: requested.file.as_str(),
        backend: backend.name,
    })?;
    let network =
        clamp_up(requested.network, backend.network).ok_or(EnforcementError::Unenforceable {
            dimension: "network",
            requested: requested.network.as_str(),
            backend: backend.name,
        })?;

    let enforced = IsolationLattice {
        process,
        file,
        network,
    };
    // Invariant: clamping up can only strengthen, never weaken.
    debug_assert!(enforced.at_least(&requested));
    let delivered = IsolationLattice {
        process: process.max(backend.delivers.process),
        file: file.max(backend.delivers.file),
        network: network.max(backend.delivers.network),
    };
    debug_assert!(delivered.at_least(&enforced));
    Ok(EnforcedIsolation {
        requested,
        enforced,
        delivered,
        backend: backend.name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isolation::IsolationLattice;

    // ── Firecracker enforces the full lattice faithfully ──────────────────

    #[test]
    fn firecracker_enforces_every_default_faithfully() {
        for requested in [
            IsolationLattice::localhost(),
            IsolationLattice::sandboxed(),
            IsolationLattice::microvm(),
            IsolationLattice::microvm_with_network(),
        ] {
            let e = require_isolation(requested, &BackendCapability::FIRECRACKER).unwrap();
            assert!(
                e.is_faithful(),
                "firecracker should enforce {requested} as-is"
            );
            assert_eq!(e.enforced, requested);
        }
    }

    /// #3220: a Firecracker pod that requests nothing still runs in a microVM
    /// with a read-only rootfs and its own network stack. The clamp leaves the
    /// request alone (faithful, so the policy is not rewritten), and `delivered`
    /// carries the floor the listing reports. Before `delivers`, the only
    /// posture on record was the clamp: `process=shared, file=unrestricted,
    /// network=host`.
    #[test]
    fn firecracker_delivers_its_floor_without_tightening_the_policy() {
        let e = require_isolation(
            IsolationLattice::localhost(),
            &BackendCapability::FIRECRACKER,
        )
        .unwrap();
        assert!(e.is_faithful(), "the floor must not rewrite the policy");
        assert_eq!(
            e.delivered,
            IsolationLattice {
                process: ProcessIsolation::MicroVM,
                file: FileIsolation::ReadOnly,
                network: NetworkIsolation::Namespaced,
            }
        );
        // A request above the floor is delivered as requested.
        let strong = IsolationLattice::microvm();
        let e = require_isolation(strong, &BackendCapability::FIRECRACKER).unwrap();
        assert_eq!(e.delivered, strong);
    }

    // ── Apple: the secure default's `Filtered` can't be enforced ──────────

    #[test]
    fn apple_strengthens_filtered_network_to_airgapped() {
        // sandboxed() = Namespaced / Sandboxed / Filtered — none of which Apple
        // enforces as-specified; all three clamp UP.
        let requested = IsolationLattice::sandboxed();
        let e = require_isolation(requested, &BackendCapability::APPLE_VZ).unwrap();

        assert_eq!(e.enforced.network, NetworkIsolation::Airgapped); // Filtered → Airgapped
        assert_eq!(e.enforced.process, ProcessIsolation::MicroVM); // Namespaced → MicroVM
        assert_eq!(e.enforced.file, FileIsolation::ReadOnly); // Sandboxed → ReadOnly

        // Never weaker, and the strengthening is recorded for audit.
        assert!(e.enforced.at_least(&requested));
        assert!(e.was_strengthened());
        let dims: Vec<_> = e.strengthenings().iter().map(|s| s.dimension).collect();
        assert_eq!(dims, vec!["process", "file", "network"]);
    }

    #[test]
    fn apple_enforces_airgapped_microvm_faithfully() {
        // The strong end of the lattice maps to Apple's strengths exactly.
        let requested = IsolationLattice::microvm(); // MicroVM / Ephemeral / Airgapped
        let e = require_isolation(requested, &BackendCapability::APPLE_VZ).unwrap();
        assert!(e.is_faithful());
    }

    #[test]
    fn apple_host_network_and_shared_are_faithful() {
        let requested = IsolationLattice::localhost(); // Shared / Unrestricted / Host
        let e = require_isolation(requested, &BackendCapability::APPLE_VZ).unwrap();
        assert!(e.is_faithful());
    }

    // ── The load-bearing safety property: enforcement is NEVER a downgrade ──

    #[test]
    fn enforced_is_always_at_least_requested() {
        use crate::isolation::{FileIsolation as F, NetworkIsolation as N, ProcessIsolation as P};
        for &p in &[P::Shared, P::Namespaced, P::MicroVM] {
            for &f in &[F::Unrestricted, F::Sandboxed, F::ReadOnly, F::Ephemeral] {
                for &n in &[N::Host, N::Namespaced, N::Filtered, N::Airgapped] {
                    let requested = IsolationLattice {
                        process: p,
                        file: f,
                        network: n,
                    };
                    // Every backend, not a hand-listed pair: a backend added to
                    // `ALL` is covered here the day it is declared.
                    for backend in BackendCapability::ALL {
                        // The property is "never a downgrade", NOT "always
                        // succeeds". A backend that cannot reach the request
                        // must refuse it; only a returned posture is claimed.
                        match require_isolation(requested, backend) {
                            Ok(e) => {
                                assert!(
                                    e.enforced.at_least(&requested),
                                    "enforced {} weaker than requested {} on {}",
                                    e.enforced,
                                    requested,
                                    backend.name
                                );
                                assert!(
                                    e.delivered.at_least(&e.enforced)
                                        && e.delivered.at_least(&backend.delivers),
                                    "delivered {} is not enforced {} joined with {}'s floor",
                                    e.delivered,
                                    e.enforced,
                                    backend.name
                                );
                            }
                            Err(EnforcementError::Unenforceable { .. }) => {}
                        }
                    }
                }
            }
        }
    }

    /// Non-vacuity for the two backends added in SECURITY_TODO #17.
    ///
    /// The generalized property above is satisfied trivially by a backend that
    /// refuses everything, and by one that accepts everything. These assert the
    /// two constants sit where they are claimed to: they admit the posture a pod
    /// gets when it names no minimum, and they refuse the microVM posture they
    /// cannot deliver. Without this, weakening `CONTAINER` to the empty
    /// capability — or widening it back to Firecracker's — would stay green.
    #[test]
    fn container_and_local_admit_the_default_posture_and_refuse_what_they_cannot_back() {
        // What a pod gets with `minimum_isolation: None` — the common case.
        let default_posture = IsolationLattice::localhost();
        for backend in [&BackendCapability::CONTAINER, &BackendCapability::LOCAL] {
            let e = require_isolation(default_posture, backend)
                .unwrap_or_else(|e| panic!("{} must admit the default posture: {e}", backend.name));
            assert!(
                e.is_faithful(),
                "{} strengthened the default posture to {}",
                backend.name,
                e.enforced
            );

            // ...and neither can back a microVM.
            let err = require_isolation(IsolationLattice::microvm(), backend)
                .expect_err("a microVM posture is not deliverable without a separate kernel");
            let EnforcementError::Unenforceable { backend: b, .. } = err;
            assert_eq!(b, backend.name);
        }

        // The floor is genuinely a floor: `local` cannot even namespace.
        assert!(
            require_isolation(IsolationLattice::sandboxed(), &BackendCapability::LOCAL).is_err(),
            "local declares process-only execution; a sandboxed posture must be refused"
        );
    }

    // ── Fail-closed when even the strongest enforceable level is too weak ──

    #[test]
    fn fails_closed_when_no_level_is_strong_enough() {
        // A contrived backend that can only do Host networking. A request for
        // Airgapped has no enforceable level ≥ it ⇒ Unenforceable, not a
        // silent downgrade to Host.
        const HOST_ONLY: BackendCapability = BackendCapability {
            name: "host-only",
            process: &[
                ProcessIsolation::Shared,
                ProcessIsolation::Namespaced,
                ProcessIsolation::MicroVM,
            ],
            file: &[
                FileIsolation::Unrestricted,
                FileIsolation::Sandboxed,
                FileIsolation::ReadOnly,
                FileIsolation::Ephemeral,
            ],
            network: &[NetworkIsolation::Host],
            delivers: NO_FLOOR,
        };
        let requested = IsolationLattice {
            process: ProcessIsolation::MicroVM,
            file: FileIsolation::Ephemeral,
            network: NetworkIsolation::Airgapped,
        };
        let err = require_isolation(requested, &HOST_ONLY).unwrap_err();
        assert_eq!(
            err,
            EnforcementError::Unenforceable {
                dimension: "network",
                requested: "airgapped",
                backend: "host-only",
            }
        );
    }
}
