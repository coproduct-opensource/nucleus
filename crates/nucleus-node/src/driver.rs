//! Substrate driver seam — which isolation backend a pod runs under.
//!
//! The `DriverKind` selected here pairs with a `portcullis::enforcement::
//! BackendCapability` (chosen by [`isolation_backend`]), which declares the
//! isolation levels the backend can enforce; [`clamp_isolation_to_backend`] clamps
//! enforced ≥ requested on every pod-create, before admission.
//! Extracted from `main.rs` so a new substrate is an additive module, not a
//! growth of the node's already-ratcheted entrypoint.

use crate::{ApiError, DriverState, NodeState};
use clap::ValueEnum;
use nucleus_spec::{PodSpec, PolicySpec};
use portcullis::enforcement::{BackendCapability, require_isolation};
use std::path::{Path, PathBuf};
use tracing::{error, warn};
use uuid::Uuid;

/// The isolation substrate the node launches pods under.
#[derive(Clone, Debug, ValueEnum)]
pub(crate) enum DriverKind {
    /// No VM isolation — process-only. Dev/test; refused in production.
    #[cfg(feature = "local-driver")]
    Local,
    /// Firecracker microVM (Linux/KVM). The production default.
    Firecracker,
    /// Container runtime.
    Container,
    /// Apple Virtualization.framework (macOS-native). Its enforcement capability
    /// is already declared (`BackendCapability::APPLE_VZ`, which
    /// [`isolation_backend`] selects for this variant); the boot driver is
    /// [`spawn_vz_pod`].
    AppleVz,
}

/// Launch a pod under Apple Virtualization.framework. **macOS-native, not yet
/// implemented** — the landing spot for the VZ boot.
///
/// When implemented it boots a `VZVirtualMachine`, carries the workload API over
/// VZ's virtio-socket (Firecracker's vsock/jailer assumptions do not port), and
/// sources the mediator key from the Secure Enclave. The enforcement clamp is
/// already in place via `BackendCapability::APPLE_VZ`, so this fills the driver
/// half of a seam whose enforcement half is done. Returns an error until then, so
/// selecting the driver fails loudly rather than silently no-op'ing.
#[allow(clippy::unused_async)] // the real VZ boot is async; the stub returns immediately
pub(crate) async fn spawn_vz_pod(
    state: &NodeState,
    pod_dir: &Path,
    spec: &PodSpec,
    id: Uuid,
) -> Result<(DriverState, Option<String>, PathBuf), ApiError> {
    let _ = (state, pod_dir, spec, id);
    Err(ApiError::Driver(
        "Apple VZ driver not yet implemented (macOS-native, Virtualization.framework) \
         — see docs/plugin-surface.md"
            .to_string(),
    ))
}

/// The isolation backend a driver enforces with.
///
/// This is a total function of the driver, and deliberately reads no
/// environment. It used to consult `NUCLEUS_ISOLATION_BACKEND`, defaulting to
/// [`BackendCapability::FIRECRACKER`] — which declares the **full** lattice — so
/// a node run with `--driver container` or `--driver local` clamped every pod
/// against Firecracker's capabilities and wrote `backend=firecracker` into the
/// spec labels. `EnforcedIsolation::is_faithful()` then returned true and the
/// certificate carried a posture nothing delivered (SECURITY_TODO #17).
///
/// The env var was introduced for the Apple-VZ case and `Container` was never
/// given an arm; the driver already carries the answer, so it is the selector.
/// The match is exhaustive on purpose: a new `DriverKind` is a compile error
/// here before it is a silently mis-declared posture.
pub(crate) fn isolation_backend(kind: &DriverKind) -> &'static BackendCapability {
    match kind {
        #[cfg(feature = "local-driver")]
        DriverKind::Local => &BackendCapability::LOCAL,
        DriverKind::Firecracker => &BackendCapability::FIRECRACKER,
        DriverKind::Container => &BackendCapability::CONTAINER,
        DriverKind::AppleVz => &BackendCapability::APPLE_VZ,
    }
}

/// Clamp the pod's requested isolation posture UP to what this node's backend
/// can actually enforce, recording requested/enforced/backend in the spec's
/// labels.
///
/// Runs on EVERY pod-create, before admission, so the certificate the node
/// issues — and therefore the policy every driver runs under — already carries
/// the enforceable posture: a pod never runs believing it holds a guarantee the
/// platform does not deliver. Until #2438 this clamp lived inside the trust
/// gate and ran only when a trust API was configured and enforcing; a node
/// with no trust API skipped it entirely.
pub(crate) fn clamp_isolation_to_backend(
    kind: &DriverKind,
    spec: &mut PodSpec,
) -> Result<(), ApiError> {
    clamp_isolation_to(spec, isolation_backend(kind))
}

/// [`clamp_isolation_to_backend`] against an explicit backend (testable
/// without a node).
pub(crate) fn clamp_isolation_to(
    spec: &mut PodSpec,
    backend: &'static BackendCapability,
) -> Result<(), ApiError> {
    let lattice = match spec.spec.resolve_policy() {
        Ok(l) => l,
        Err(e) => {
            // Admission resolves the same policy and refuses the spec; nothing
            // to clamp until there is a lattice.
            warn!(error = %e, "isolation clamp: policy resolution failed");
            return Ok(());
        }
    };
    let enforced = match require_isolation(lattice.effective_minimum_isolation(), backend) {
        Ok(enforced) => enforced,
        Err(err) => {
            // REFUSE. This arm was previously `warn` + return, on the reasoning
            // that it was unreachable for the built-in backends and that keeping
            // the requested posture was "fail safe". Neither holds: it is
            // reachable now that `CONTAINER` and `LOCAL` declare only the floor
            // (SECURITY_TODO #17), and keeping the requested posture is exactly
            // the outcome this function exists to prevent — a pod running while
            // believing it holds a guarantee the platform does not deliver.
            //
            // A silent downgrade IS the failure mode: the operator asked for
            // enforcement, did not get it, and had no way to tell. The error
            // names the dimension, the request and the backend so the refusal is
            // actionable rather than a wall.
            error!(
                backend = backend.name,
                error = %err,
                "isolation clamp: required isolation is unenforceable on this backend"
            );
            return Err(ApiError::InvalidSpec(format!(
                "isolation unenforceable on this node: {err}"
            )));
        }
    };

    spec.record_isolation(enforced);

    if enforced.was_strengthened() {
        warn!(
            backend = backend.name,
            requested = %enforced.requested,
            enforced = %enforced.enforced,
            "isolation strengthened to the backend-enforceable posture"
        );
        spec.spec.policy = PolicySpec::Inline {
            lattice: Box::new(lattice.with_minimum_isolation(enforced.enforced)),
        };
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use portcullis::{FileIsolation, IsolationLattice, NetworkIsolation, ProcessIsolation};

    fn spec_with(policy: PolicySpec) -> PodSpec {
        use nucleus_spec::PodSpecInner;
        use std::path::PathBuf;
        PodSpec::new(PodSpecInner {
            work_dir: PathBuf::from("/workspace"),
            timeout_seconds: 3600,
            policy,
            budget_model: None,
            resources: None,
            network: None,
            image: None,
            credentialed_egress: Vec::new(),
            workload: None,
            vsock: None,
            seccomp: None,
            cgroup: None,
            audit_sink: None,
            credentials: None,
        })
    }

    fn label<'a>(spec: &'a PodSpec, key: &str) -> Option<&'a str> {
        spec.metadata.labels.get(key).map(String::as_str)
    }

    /// Firecracker enforces the full lattice: the posture labels are written
    /// on every pod, the request is faithful, and the policy is untouched.
    #[test]
    fn firecracker_is_faithful_and_touches_only_labels() {
        let mut spec = spec_with(PolicySpec::Profile {
            name: "default".to_string(),
        });
        clamp_isolation_to(&mut spec, &BackendCapability::FIRECRACKER)
            .expect("firecracker enforces the full lattice");

        assert_eq!(
            label(&spec, "isolation.coproduct.one/backend"),
            Some("firecracker")
        );
        assert_eq!(
            label(&spec, "isolation.coproduct.one/requested"),
            label(&spec, "isolation.coproduct.one/enforced"),
            "firecracker enforces the full lattice"
        );
        match &spec.spec.policy {
            PolicySpec::Profile { name } => assert_eq!(name, "default"),
            PolicySpec::Inline { .. } => panic!("a faithful clamp must not rewrite the policy"),
        }
    }

    /// Apple VZ has no host-side egress allowlist: a `Filtered` request is
    /// strengthened to `Airgapped`, and the policy is rewritten so the pod —
    /// and the certificate minted from this request — carry the posture the
    /// backend actually delivers.
    #[test]
    fn apple_vz_strengthens_and_rewrites_the_policy() {
        let requested = spec_with(PolicySpec::Profile {
            name: "default".to_string(),
        })
        .spec
        .resolve_policy()
        .expect("default profile resolves")
        .with_minimum_isolation(IsolationLattice::new(
            ProcessIsolation::MicroVM,
            FileIsolation::ReadOnly,
            NetworkIsolation::Filtered,
        ));
        let mut spec = spec_with(PolicySpec::Inline {
            lattice: Box::new(requested),
        });
        clamp_isolation_to(&mut spec, &BackendCapability::APPLE_VZ)
            .expect("apple-vz clamps up rather than refusing this posture");

        assert_eq!(
            label(&spec, "isolation.coproduct.one/backend"),
            Some("apple-vz")
        );
        assert_ne!(
            label(&spec, "isolation.coproduct.one/requested"),
            label(&spec, "isolation.coproduct.one/enforced"),
            "the strengthening is recorded"
        );
        match &spec.spec.policy {
            PolicySpec::Inline { lattice } => assert_eq!(
                lattice.effective_minimum_isolation().network,
                NetworkIsolation::Airgapped,
                "Filtered is not enforceable on VZ; clamped up, never down"
            ),
            PolicySpec::Profile { .. } => panic!("a strengthened clamp must rewrite the policy"),
        }
    }

    /// The clamp is unconditional and precedes admission (#2438): it sits at
    /// the top level of `create_pod_internal`, not inside the trust-gate branch.
    #[test]
    fn the_clamp_is_wired_before_admission_unconditionally() {
        let main = include_str!("main.rs");
        let clamp = main
            .find("driver::clamp_isolation_to_backend(&state.driver, &mut spec)?")
            .expect("the clamp is called from main.rs, with the node's own driver, and its refusal propagated");
        let admit = main
            .find("state.authority.admit(&admission, &spec, id)")
            .expect("admission is called from main.rs");
        assert!(clamp < admit, "the clamp must run before admission");
        let indent = main[..clamp].rsplit('\n').next().unwrap_or("");
        assert_eq!(
            indent, "    ",
            "the clamp must be at function-body level, not under a condition"
        );
    }

    // ── SECURITY_TODO #17: the backend is the driver's, not the environment's ──

    /// The capability is a total function of the driver. Before this, the
    /// selector was `NUCLEUS_ISOLATION_BACKEND` defaulting to Firecracker, so a
    /// container node clamped against the FULL lattice and labelled itself
    /// `backend=firecracker` — a posture nothing on that path delivers.
    #[test]
    fn the_backend_is_the_drivers_not_the_environments() {
        assert_eq!(
            isolation_backend(&DriverKind::Container).name,
            "container",
            "a container node must not inherit Firecracker's capability"
        );
        assert_eq!(
            isolation_backend(&DriverKind::Firecracker).name,
            "firecracker"
        );
        assert_eq!(isolation_backend(&DriverKind::AppleVz).name, "apple-vz");
        #[cfg(feature = "local-driver")]
        assert_eq!(isolation_backend(&DriverKind::Local).name, "local");
    }

    /// The common case must not regress into a refusal: a pod that names no
    /// minimum gets `localhost()` (Shared/Unrestricted/Host), which every
    /// backend can back. If this ever reds, the container floor was set below
    /// the default posture and every ordinary pod is being refused.
    #[test]
    fn a_container_pod_with_no_minimum_is_admitted_and_labelled_container() {
        let mut spec = spec_with(PolicySpec::Profile {
            name: "default".to_string(),
        });
        clamp_isolation_to(&mut spec, &BackendCapability::CONTAINER)
            .expect("the default posture is deliverable on a container");

        assert_eq!(
            label(&spec, "isolation.coproduct.one/backend"),
            Some("container"),
            "the label must name the backend that actually ran the clamp"
        );
    }

    /// The refusal this item exists for: a container cannot deliver a microVM,
    /// so a pod asking for one is REFUSED rather than told it got it. This arm
    /// used to `warn!` and return, leaving the spec unclamped.
    #[test]
    fn a_container_pod_asking_for_a_microvm_is_refused_naming_the_dimension() {
        let requested = spec_with(PolicySpec::Profile {
            name: "default".to_string(),
        })
        .spec
        .resolve_policy()
        .expect("default profile resolves")
        .with_minimum_isolation(IsolationLattice::new(
            ProcessIsolation::MicroVM,
            FileIsolation::Unrestricted,
            NetworkIsolation::Host,
        ));
        let mut spec = spec_with(PolicySpec::Inline {
            lattice: Box::new(requested),
        });

        let err = clamp_isolation_to(&mut spec, &BackendCapability::CONTAINER)
            .expect_err("a container has no separate kernel; this must not be granted in name");
        let msg = err.to_string();
        assert!(
            msg.contains("process") && msg.contains("container"),
            "the refusal must name the dimension and the backend, not just fail: {msg}"
        );
        assert!(
            label(&spec, "isolation.coproduct.one/enforced").is_none(),
            "a refused clamp must not leave a posture label asserting enforcement"
        );
    }
}
