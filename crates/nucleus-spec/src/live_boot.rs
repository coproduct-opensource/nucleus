//! The raw evidence one live boot leaves behind, as one schema for the writer
//! (the live collector in `nucleus-cli`) and the reader (`cargo xtask
//! live-boot-evidence`, which appraises it with the public verifiers only).
//!
//! Nothing here is verified evidence. It is what an operator would hand a
//! stranger: files, the request that produced them, and what the collector
//! measured on the host while the pod ran. The appraiser decides what holds.

use serde::{Deserialize, Serialize};

/// The collection document's schema.
pub const SCHEMA: &str = "nucleus-live-boot-collection/v1";

/// The collection document's file name in the bundle directory.
pub const COLLECTION_FILE: &str = "collection.json";

/// The declared artifact the workload writes, by name.
pub const ARTIFACT_NAME: &str = "note";

/// Its workspace path, relative to the pod's `work_dir`.
pub const ARTIFACT_PATH: &str = "live-boot-note.txt";

/// The artifact's exact bytes for a run with this nonce. The workload writes
/// them and the appraiser compares the verified bytes with them, so one
/// function names them for both (ADR 0007 G-1).
#[must_use]
pub fn artifact_bytes(nonce: &str) -> String {
    format!("live-boot-evidence {nonce}\n")
}

/// Everything the collector wrote, and what it measured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Collection {
    /// [`SCHEMA`].
    pub schema: String,
    /// The appraiser's nonce, echoed into the artifact and the effect request.
    pub nonce: String,
    /// The pod that ran the posture workload and signed the execution receipt.
    pub execution_pod: String,
    /// The pod that made one credentialed request, for the host-effect journal.
    pub effect_pod: String,
    /// The bundle's files, each a name relative to the bundle directory.
    pub files: Files,
    /// The node binaries as they ran, keyed by the path a release names.
    pub measured: Vec<Measured>,
    /// What the receipt says about the node's platform, and the document it
    /// names when it names one.
    pub node_evidence: NodeEvidence,
    /// Wall-clock milliseconds, recorded for a later ratchet.
    pub timings: Timings,
}

/// The bundle's files, relative to the bundle directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Files {
    /// The PodSpec the collector requested.
    pub spec: String,
    /// The node's authenticated admission record for the execution pod.
    pub admission: String,
    /// The environment the request set, as a name/value JSON map.
    pub environment_inputs: String,
    /// The artifact selection the receipt was collected with.
    pub artifact_selection: String,
    /// `{receipt, artifacts}` exactly as the node returned it.
    pub artifacts_bundle: String,
    /// The execution receipt alone (the bundle's `receipt`).
    pub receipt: String,
    /// The workload's exact stdout bytes.
    pub stdout: String,
    /// The workload's exact stderr bytes.
    pub stderr: String,
    /// The execution pod's guest console (`firecracker.log`).
    pub guest_console: String,
    /// The node's own log.
    pub node_log: String,
    /// The host key (hex), exported from the node's key file.
    pub host_key: String,
    /// The effect pod's signed authorization journal.
    pub host_effects: String,
    /// The effect pod's signed outcome journal.
    pub host_effect_outcomes: String,
    /// The effect pod's guest console (`firecracker.log`): where its shadow
    /// telemetry is printed.
    pub effect_console: String,
    /// Every pod's shadow disagreement records, concatenated. Written even when
    /// empty, so a bundle that lacks it is one whose record was withheld.
    pub host_decide_disagreements: String,
}

impl Files {
    /// The names the collector writes.
    #[must_use]
    pub fn standard() -> Self {
        let s = |n: &str| n.to_string();
        Self {
            spec: s("spec.json"),
            admission: s("admission.json"),
            environment_inputs: s("environment-inputs.json"),
            artifact_selection: s("artifact-selection.json"),
            artifacts_bundle: s("artifacts-bundle.json"),
            receipt: s("receipt.json"),
            stdout: s("stdout.bin"),
            stderr: s("stderr.bin"),
            guest_console: s("guest-console.log"),
            node_log: s("node.log"),
            host_key: s("host-key.hex"),
            host_effects: s("host-effects.jsonl"),
            host_effect_outcomes: s("host-effect-outcomes.jsonl"),
            effect_console: s("effect-console.log"),
            host_decide_disagreements: s(crate::host_decide_telemetry::DISAGREEMENT_LOG),
        }
    }
}

/// One node binary as it ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Measured {
    /// The path a release reference manifest names (`/usr/local/bin/<bin>`).
    pub path: String,
    /// SHA-256 of the bytes, hex.
    pub sha256: String,
    /// Where the bytes were read.
    pub how: MeasuredHow,
}

/// Where a measurement's bytes were read. Two different claims, so two cases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum MeasuredHow {
    /// `/proc/<pid>/exe` of a running process: the bytes that executed.
    ProcessExe {
        /// The process.
        pid: u32,
        /// Where the kernel says the executable lives.
        exe: String,
    },
    /// The file the node was configured to execute. Used for the jailer,
    /// which `exec`s Firecracker and so is never running to be read.
    ConfiguredFile,
}

/// The node platform, as the receipt states it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NodeEvidence {
    /// The receipt says the node holds no platform evidence, and why.
    Unattested {
        /// The receipt's reason.
        reason: String,
    },
    /// The receipt names an evidence document, saved under `file`.
    Evidence {
        /// The bundle file holding the document's exact bytes.
        file: String,
        /// The digest the receipt names.
        sha256: String,
        /// The epoch the receipt names.
        epoch: u64,
    },
}

/// Wall-clock milliseconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Timings {
    /// The fresh node's start until it answered health.
    pub node_ready_ms: u64,
    /// `POST /v1/pods` for the execution pod, until the node answered.
    pub pod_create_ms: u64,
    /// From the create request until the guest's supervisor first answered.
    pub guest_proxy_ready_ms: u64,
    /// From the create request until the supervisor reported the exit.
    pub workload_exit_ms: u64,
    /// `POST /v1/pods` for the effect pod.
    pub effect_pod_create_ms: u64,
    /// The whole collection.
    pub total_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_collection_round_trips_and_refuses_unknown_fields() {
        let c = Collection {
            schema: SCHEMA.into(),
            nonce: "n".into(),
            execution_pod: "a".into(),
            effect_pod: "b".into(),
            files: Files::standard(),
            measured: vec![Measured {
                path: "/usr/local/bin/nucleus-node".into(),
                sha256: "00".repeat(32),
                how: MeasuredHow::ProcessExe {
                    pid: 7,
                    exe: "/usr/local/bin/nucleus-node".into(),
                },
            }],
            node_evidence: NodeEvidence::Unattested {
                reason: "no TPM".into(),
            },
            timings: Timings {
                node_ready_ms: 1,
                pod_create_ms: 2,
                guest_proxy_ready_ms: 3,
                workload_exit_ms: 4,
                effect_pod_create_ms: 5,
                total_ms: 6,
            },
        };
        let mut json = serde_json::to_value(&c).unwrap();
        assert_eq!(
            serde_json::from_value::<Collection>(json.clone()).unwrap(),
            c
        );
        json["surprise"] = true.into();
        assert!(serde_json::from_value::<Collection>(json).is_err());
        assert_eq!(artifact_bytes("n"), "live-boot-evidence n\n");
    }
}
