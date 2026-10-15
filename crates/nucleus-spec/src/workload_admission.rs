//! Public admission metadata obtained from an authenticated node, separately
//! from execution evidence. This is not a signed receipt or a build verdict.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::workload_result::MEDIATOR_BINDINGS;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadAdmission {
    pub pod_id: String,
    pub created_at_unix: u64,
    pub source_commit: String,
    pub source_tree: String,
    pub gate: String,
    /// Identity of the effective spec after host admission.
    pub program_digest: String,
    pub architecture: String,
    pub artifacts: BTreeMap<String, String>,
    pub session_id: String,
    pub issuer_kid: String,
    /// Public Ed25519 key only. Enrollment must authenticate the node and
    /// compare this with the controller's configured signer when one exists.
    pub verifying_key: [u8; 32],
    /// The environment entries the runtime injects into the workload and the
    /// execution receipt's `environment_inputs_sha256` binds: today one
    /// `NUCLEUS_EGRESS_<NAME>_URL` per declared credentialed upstream, computed
    /// by `workload_egress::injected_env`, the function the launcher calls.
    /// Names and local addresses only; no credential is ever here.
    ///
    /// Required, with no serde default (ADR 0007 B-2): a record from a node
    /// that predates this field fails to parse by its name rather than reading
    /// as "the runtime injected nothing". An empty map is the node saying so.
    pub runtime_environment_inputs: BTreeMap<String, String>,
}

/// Why declared environment inputs could not be combined with an admission's
/// runtime-injected ones.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnvironmentInputsError {
    /// The declared inputs name a mediator binding, which the environment
    /// commitment omits; accepting it would silently ignore a value.
    #[error("environment inputs must omit the mediator-injected binding {name}")]
    MediatorBinding { name: String },
    /// The declared inputs restate a name the runtime injects. The runtime's
    /// value wins at launch, so the admission record is the one source for it.
    #[error(
        "environment input {name} is injected by the runtime; it is derived from the \
         admission record and must not be restated"
    )]
    RuntimeInjected { name: String },
}

impl WorkloadAdmission {
    /// The complete environment inputs the receipt's `environment_inputs_sha256`
    /// binds: the operator's `declared` inputs (the workload spec's `env` and
    /// resolved defaults) together with the runtime-injected entries this
    /// record carries.
    ///
    /// # Errors
    /// A declared or runtime name is a mediator binding, or a declared name is
    /// one the runtime injects. Each is named.
    pub fn environment_inputs(
        &self,
        declared: &BTreeMap<String, String>,
    ) -> Result<BTreeMap<String, String>, EnvironmentInputsError> {
        let names = declared
            .keys()
            .chain(self.runtime_environment_inputs.keys());
        if let Some(name) = names
            .into_iter()
            .find(|name| MEDIATOR_BINDINGS.contains(&name.as_str()))
        {
            return Err(EnvironmentInputsError::MediatorBinding { name: name.clone() });
        }
        if let Some(name) = declared
            .keys()
            .find(|name| self.runtime_environment_inputs.contains_key(*name))
        {
            return Err(EnvironmentInputsError::RuntimeInjected { name: name.clone() });
        }
        let mut inputs = declared.clone();
        inputs.extend(self.runtime_environment_inputs.clone());
        Ok(inputs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "NUCLEUS_EGRESS_MODEL_API_URL";

    fn admission(runtime: &[(&str, &str)]) -> WorkloadAdmission {
        WorkloadAdmission {
            pod_id: "attempt-1".into(),
            created_at_unix: 10,
            source_commit: String::new(),
            source_tree: String::new(),
            gate: String::new(),
            program_digest: "program".into(),
            architecture: "aarch64".into(),
            artifacts: BTreeMap::new(),
            session_id: "attempt-1".into(),
            issuer_kid: "node".into(),
            verifying_key: [7; 32],
            runtime_environment_inputs: runtime
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        }
    }

    #[test]
    fn declared_and_runtime_inputs_are_combined() {
        let declared = BTreeMap::from([("PATH".to_string(), "/usr/bin".to_string())]);
        let inputs = admission(&[(URL, "unix:///door/v1/egress/model-api")])
            .environment_inputs(&declared)
            .unwrap();
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs[URL], "unix:///door/v1/egress/model-api");
        assert_eq!(inputs["PATH"], "/usr/bin");
    }

    #[test]
    fn restating_a_runtime_injected_name_is_refused_by_name() {
        let declared = BTreeMap::from([(URL.to_string(), "anything".to_string())]);
        let err = admission(&[(URL, "unix:///door/v1/egress/model-api")])
            .environment_inputs(&declared)
            .unwrap_err();
        assert_eq!(
            err,
            EnvironmentInputsError::RuntimeInjected { name: URL.into() }
        );
    }

    #[test]
    fn a_mediator_binding_on_either_side_is_refused_by_name() {
        for name in MEDIATOR_BINDINGS {
            let declared = BTreeMap::from([(name.to_string(), "x".to_string())]);
            assert_eq!(
                admission(&[]).environment_inputs(&declared).unwrap_err(),
                EnvironmentInputsError::MediatorBinding { name: name.into() }
            );
            assert_eq!(
                admission(&[(name, "x")])
                    .environment_inputs(&BTreeMap::new())
                    .unwrap_err(),
                EnvironmentInputsError::MediatorBinding { name: name.into() }
            );
        }
    }

    #[test]
    fn a_record_without_the_runtime_inputs_fails_to_parse_by_name() {
        let mut value = serde_json::to_value(admission(&[])).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("runtime_environment_inputs");
        let err = serde_json::from_value::<WorkloadAdmission>(value)
            .unwrap_err()
            .to_string();
        assert!(err.contains("runtime_environment_inputs"), "{err}");
    }
}
