//! Substrate driver seam — which isolation backend a pod runs under.
//!
//! The `DriverKind` selected here pairs with a `portcullis::enforcement::
//! BackendCapability` (chosen in `trust_gate::isolation_backend`), which declares
//! the isolation levels the backend can enforce and clamps enforced ≥ requested.
//! Extracted from `main.rs` so a new substrate is an additive module, not a
//! growth of the node's already-ratcheted entrypoint.

use crate::{ApiError, DriverState, NodeState};
use clap::ValueEnum;
use nucleus_spec::PodSpec;
use std::path::{Path, PathBuf};
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
    /// `trust_gate::isolation_backend` for the `apple-vz` backend); the boot
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
