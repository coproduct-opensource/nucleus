//! Read-only observation of the configured workload by its supervising proxy.
//! This is transport data, not a signed claim or proof of microVM isolation.

use serde::{Deserialize, Serialize};

/// The privilege boundary actually installed when the process was spawned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadIsolation {
    /// Distinct uid with the launch hardening hook applied.
    UidIsolated,
    /// Local development or a launch without a distinct hardened uid.
    Unconfined,
}

/// Whether the spec supplies its existing program identity. This is a digest
/// of declared inputs, not proof that the host measured them or that every
/// external input is pinned. Kernel and rootfs digest declarations are required
/// when an image is present; optional data/scratch pins need separate validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProgramBinding {
    Bound { digest: String },
    Unavailable { reason: String },
}

/// A supervisor observation. Missing evidence and unfinished work cannot be
/// confused with an exited workload, even when a client has just connected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkloadResult {
    NotConfigured,
    Running,
    Exited {
        /// `None` means no normal exit code (for example, a signal).
        exit_code: Option<i32>,
        /// Hashes cover every raw byte, including invalid UTF-8 and no newline.
        stdout_sha256: String,
        stderr_sha256: String,
        /// The launch hash describes authority inventory, not command bytes.
        launch_hash: String,
        program: ProgramBinding,
        isolation: WorkloadIsolation,
    },
    /// The supervisor could not collect a complete observation.
    Unavailable {
        reason: String,
    },
}
