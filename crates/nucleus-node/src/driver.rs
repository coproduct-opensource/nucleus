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
    /// is already declared (`BackendCapability::APPLE_VZ`, selected by
    /// [`isolation_backend`] for the `apple-vz` backend); the boot
    /// driver is [`spawn_vz_pod`].
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

/// The isolation backend this node enforces with. Defaults to Firecracker
/// (Linux/KVM — the full lattice); set `NUCLEUS_ISOLATION_BACKEND=apple-vz` on a
/// macOS `Virtualization.framework` host so un-enforceable levels (no host
/// egress allowlist, no namespaces tier) are clamped UP to what VZ delivers.
pub(crate) fn isolation_backend() -> &'static BackendCapability {
    match std::env::var("NUCLEUS_ISOLATION_BACKEND").as_deref() {
        Ok("apple-vz") => &BackendCapability::APPLE_VZ,
        _ => &BackendCapability::FIRECRACKER,
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
pub(crate) fn clamp_isolation_to_backend(spec: &mut PodSpec) {
    clamp_isolation_to(spec, isolation_backend());
}

/// [`clamp_isolation_to_backend`] against an explicit backend (testable
/// without the environment).
pub(crate) fn clamp_isolation_to(spec: &mut PodSpec, backend: &'static BackendCapability) {
    let lattice = match spec.spec.resolve_policy() {
        Ok(l) => l,
        Err(e) => {
            // Admission resolves the same policy and refuses the spec; nothing
            // to clamp until there is a lattice.
            warn!(error = %e, "isolation clamp: policy resolution failed");
            return;
        }
    };
    let enforced = match require_isolation(lattice.effective_minimum_isolation(), backend) {
        Ok(enforced) => enforced,
        Err(err) => {
            // Unreachable for the built-in backends (their top level is always
            // enforceable); a misconfigured custom backend could reach here.
            // Fail safe: keep the requested posture and surface the error
            // rather than silently under-enforcing.
            error!(
                backend = backend.name,
                error = %err,
                "isolation clamp: required isolation is unenforceable on this backend"
            );
            return;
        }
    };

    let labels = &mut spec.metadata.labels;
    labels.insert(
        "isolation.coproduct.one/requested".to_string(),
        enforced.requested.to_string(),
    );
    labels.insert(
        "isolation.coproduct.one/enforced".to_string(),
        enforced.enforced.to_string(),
    );
    labels.insert(
        "isolation.coproduct.one/backend".to_string(),
        backend.name.to_string(),
    );

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
        clamp_isolation_to(&mut spec, &BackendCapability::FIRECRACKER);

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
        clamp_isolation_to(&mut spec, &BackendCapability::APPLE_VZ);

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
            .find("driver::clamp_isolation_to_backend(&mut spec)")
            .expect("the clamp is called from main.rs");
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
}
