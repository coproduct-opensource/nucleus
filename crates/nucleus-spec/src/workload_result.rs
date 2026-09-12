//! Read-only observation of the configured workload by its supervising proxy.
//! This is transport data, not a signed claim or proof of microVM isolation.

use serde::{Deserialize, Serialize};

/// Per-artifact and per-bundle raw-byte limit for build output transfer.
pub const MAX_ARTIFACT_BYTES: usize = 256 * 1024 * 1024;

/// The exact admitted environment, split into stable inputs and a complete
/// per-attempt commitment. Only the two mediator-injected bindings are omitted
/// from inputs; an arbitrary `NUCLEUS_*` name is still an input.
/// This split does not prove the workload ignores the injected bindings and
/// does not license cache reuse without a separate noninterference boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentIdentity {
    pub inputs_sha256: String,
    pub complete_sha256: String,
}

impl EnvironmentIdentity {
    pub fn of(env: &std::collections::BTreeMap<String, String>) -> Self {
        use sha2::{Digest, Sha256};
        let mut inputs = Sha256::new();
        inputs.update(b"nucleus.workload-environment.inputs.v1\n");
        let mut complete = Sha256::new();
        complete.update(b"nucleus.workload-environment.complete.v1\n");
        for (name, value) in env {
            let runtime_binding = matches!(
                name.as_str(),
                "NUCLEUS_TOOL_PROXY_URL" | "NUCLEUS_TOOL_PROXY_AUTH_SECRET"
            );
            // Length prefixes distinguish boundaries without escaping. BTreeMap
            // fixes order; no secret value is emitted by this commitment.
            for bytes in [name.as_bytes(), value.as_bytes()] {
                complete.update((bytes.len() as u64).to_be_bytes());
                complete.update(bytes);
                if !runtime_binding {
                    inputs.update((bytes.len() as u64).to_be_bytes());
                    inputs.update(bytes);
                }
            }
        }
        Self {
            inputs_sha256: hex::encode(inputs.finalize()),
            complete_sha256: hex::encode(complete.finalize()),
        }
    }
}

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
        environment: EnvironmentIdentity,
        program: ProgramBinding,
        isolation: WorkloadIsolation,
    },
    /// The supervisor could not collect a complete observation.
    Unavailable {
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn environment_inputs_bind_values_and_do_not_trust_runtime_looking_names() {
        let base = BTreeMap::from([
            ("PATH".into(), "/pinned/bin".into()),
            ("NUCLEUS_EGRESS_FAKE".into(), "first".into()),
            ("NUCLEUS_TOOL_PROXY_URL".into(), "http://127.0.0.1:1".into()),
            ("NUCLEUS_TOOL_PROXY_AUTH_SECRET".into(), "attempt-1".into()),
        ]);
        let before = EnvironmentIdentity::of(&base);
        for name in ["PATH", "NUCLEUS_EGRESS_FAKE"] {
            let mut changed = base.clone();
            changed.insert(name.into(), "different".into());
            let after = EnvironmentIdentity::of(&changed);
            assert_ne!(before.inputs_sha256, after.inputs_sha256);
            assert_ne!(before.complete_sha256, after.complete_sha256);
        }
        for name in ["NUCLEUS_TOOL_PROXY_URL", "NUCLEUS_TOOL_PROXY_AUTH_SECRET"] {
            let mut changed = base.clone();
            changed.insert(name.into(), "different attempt".into());
            let after = EnvironmentIdentity::of(&changed);
            assert_eq!(before.inputs_sha256, after.inputs_sha256);
            assert_ne!(before.complete_sha256, after.complete_sha256);
        }
    }

    #[test]
    fn environment_commitments_distinguish_entry_boundaries() {
        let first = BTreeMap::from([("ab".into(), "c".into())]);
        let second = BTreeMap::from([("a".into(), "bc".into())]);
        assert_ne!(
            EnvironmentIdentity::of(&first),
            EnvironmentIdentity::of(&second)
        );
    }
}
