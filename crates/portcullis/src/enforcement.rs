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
//! Pairing the isolation gate with a verified authority ([`require_enforced`])
//! yields the fabric's invariant: **no action without (a) a verified authority
//! and (b) an enforceable isolation posture.**
//!
//! This module is pure and `ring`-free, so it compiles on WASM and into a zkVM
//! guest alongside the rest of the portable decision layer.

use crate::isolation::{FileIsolation, IsolationLattice, NetworkIsolation, ProcessIsolation};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

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
    };
}

/// The outcome of mapping a requested posture onto a backend: what was asked
/// for, and what will actually be enforced. By construction `enforced` is
/// at-least-as-strong as `requested` on **every** dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EnforcedIsolation {
    /// What the decision asked for.
    pub requested: IsolationLattice,
    /// What the backend will actually enforce (≥ `requested`, never weaker).
    pub enforced: IsolationLattice,
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
    Ok(EnforcedIsolation {
        requested,
        enforced,
        backend: backend.name,
    })
}

/// An authority that has cleared the enforcement gate: a verified authority
/// `A` (a `DecisionToken`, a portcullis `VerifiedPermissions`, or a PCA
/// `Certificate`'s verified outcome) **and** an enforceable isolation posture.
///
/// Constructing one is the fabric's act-gate: you cannot obtain `Authorized`
/// without both halves, so an enforcement point that requires it cannot act on
/// a decision whose isolation the platform can't back.
#[derive(Debug, Clone, Copy)]
pub struct Authorized<A> {
    /// The verified authority (proof that the action is permitted).
    pub authority: A,
    /// The enforcement posture the backend will apply (≥ requested).
    pub isolation: EnforcedIsolation,
}

/// The fabric act-gate: combine an already-**verified** authority with an
/// enforceable isolation posture. Backend-agnostic — `authority` may be any
/// verified-permission proof (portcullis `VerifiedPermissions`, a kernel
/// `DecisionToken`, or a PCA certificate's `VerifiedAuthority`). Returns
/// [`Authorized`] only when the backend can enforce a posture ≥ the request.
pub fn require_enforced<A>(
    authority: A,
    requested: IsolationLattice,
    backend: &BackendCapability,
) -> Result<Authorized<A>, EnforcementError> {
    let isolation = require_isolation(requested, backend)?;
    Ok(Authorized {
        authority,
        isolation,
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
                    for backend in [
                        &BackendCapability::FIRECRACKER,
                        &BackendCapability::APPLE_VZ,
                    ] {
                        let e = require_isolation(requested, backend).unwrap();
                        assert!(
                            e.enforced.at_least(&requested),
                            "enforced {} weaker than requested {} on {}",
                            e.enforced,
                            requested,
                            backend.name
                        );
                    }
                }
            }
        }
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

    // ── The act-gate ties a verified authority to an enforceable posture ──

    #[test]
    fn require_enforced_carries_authority_and_posture() {
        // The authority stands in for any verified-permission proof.
        let authority = "verified:spiffe://agent/coder-042";
        let authorized = require_enforced(
            authority,
            IsolationLattice::sandboxed(),
            &BackendCapability::APPLE_VZ,
        )
        .expect("apple can enforce a posture ≥ sandboxed (by strengthening)");
        assert_eq!(authorized.authority, "verified:spiffe://agent/coder-042");
        assert_eq!(
            authorized.isolation.enforced.network,
            NetworkIsolation::Airgapped
        );
    }

    /// End-to-end: a **verified portcullis delegation** (the "who-may" answer,
    /// portcullis's own `VerifiedPermissions`) flows through the act-gate and
    /// emerges as an [`Authorized`] carrying both the delegation and the
    /// enforceable posture — on Apple, the secure default's `Filtered` egress
    /// is strengthened to `Airgapped`, never weakened. This is the unification:
    /// one gate consumes a capability delegation exactly as it would a PCA
    /// policy decision.
    #[test]
    fn require_enforced_accepts_a_verified_portcullis_delegation() {
        use crate::certificate::{SinkScope, VerifiedPermissions};
        use crate::PermissionLattice;

        let delegation = VerifiedPermissions::new(
            PermissionLattice::restrictive(),
            2,
            "spiffe://nucleus.local/human/alice".into(),
            "spiffe://nucleus.local/agent/coder-042".into(),
            SinkScope::default(),
        );

        let authorized = require_enforced(
            delegation,
            IsolationLattice::sandboxed(),
            &BackendCapability::APPLE_VZ,
        )
        .expect("a verified delegation + an enforceable posture → authorized");

        // The delegation rides through intact …
        assert_eq!(authorized.authority.chain_depth, 2);
        assert_eq!(
            authorized.authority.leaf_identity,
            "spiffe://nucleus.local/agent/coder-042"
        );
        // … and the posture was strengthened (Filtered → Airgapped), not weakened.
        assert_eq!(
            authorized.isolation.enforced.network,
            NetworkIsolation::Airgapped
        );
        assert!(authorized
            .isolation
            .enforced
            .at_least(&authorized.isolation.requested));
    }
}
