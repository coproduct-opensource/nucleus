use serde::{Deserialize, Serialize};

pub use nucleus_ci_verdict::execution::NamespaceSetup;

/// Namespace placement requested for the workload. Runtime placement retains
/// existing behavior; private setup is enforced before any workload code runs.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkloadNamespace {
    /// Use the runtime's existing namespaces, with ordinary workload confinement.
    Runtime {},
    /// Fresh user/network namespaces with explicitly selected loopback state. This does not
    /// grant namespace capabilities or access to runtime loopback services.
    PrivateUserNetwork {
        /// Identity inside the new user namespace; outer identity is the
        /// runtime's resolved workload UID.
        inner_uid: u32,
        /// Whether to raise the otherwise-down loopback interface.
        loopback: bool,
    },
}

impl WorkloadNamespace {
    /// Expected launch description; this does not establish that setup ran.
    pub fn expected(self, outer_uid: u32) -> NamespaceSetup {
        match self {
            Self::Runtime {} => NamespaceSetup::Runtime {},
            Self::PrivateUserNetwork {
                inner_uid,
                loopback,
            } => NamespaceSetup::PrivateUserNetwork {
                outer_uid,
                inner_uid,
                loopback,
            },
        }
    }
    pub(crate) fn runtime() -> Self {
        Self::Runtime {}
    }
    pub(crate) fn is_runtime(&self) -> bool {
        matches!(self, Self::Runtime {})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WorkloadSpec;

    #[test]
    fn namespace_request_is_strict_and_runtime_preserves_wire_shape() {
        let original = serde_json::json!({"command":"/usr/bin/true","args":[],"env":{},"uid":null});
        let spec: WorkloadSpec = serde_json::from_value(original.clone()).unwrap();
        assert_eq!(spec.namespace, WorkloadNamespace::Runtime {});
        assert_eq!(serde_json::to_value(&spec).unwrap(), original);
        let mut private = original.clone();
        private["namespace"] =
            serde_json::json!({"kind":"private_user_network","inner_uid":1000,"loopback":true});
        let parsed: WorkloadSpec = serde_json::from_value(private.clone()).unwrap();
        assert_eq!(
            parsed.namespace,
            WorkloadNamespace::PrivateUserNetwork {
                inner_uid: 1000,
                loopback: true
            }
        );
        assert_eq!(serde_json::to_value(parsed).unwrap(), private);
        for bad in [
            serde_json::json!({"kind":"private_user_network","inner_uid":0,"loopback":true,"inherit_credentials":true}),
            serde_json::json!({"kind":"private_user_network","inner_uid":0}),
            serde_json::json!({"kind":"runtime","inner_uid":0}),
            serde_json::json!({"kind":"unrestricted"}),
        ] {
            let mut request = original.clone();
            request["namespace"] = bad;
            assert!(serde_json::from_value::<WorkloadSpec>(request).is_err());
        }
    }
}
