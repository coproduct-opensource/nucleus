//! The namespace placement a workload requests, and what this runtime admits.
//!
//! # What is published, and what is refused
//!
//! The wire types are complete: a spec can name
//! [`WorkloadNamespace::PrivateUserNetwork`], and an execution claim
//! (`nucleus.execution.v2`) carries the [`NamespaceSetup`] the runtime
//! recorded, which the verifier binds against an independent expectation.
//!
//! The trusted setup that would make a private namespace TRUE is not in this
//! runtime. So [`WorkloadNamespace::admit`] is the one decider, and it admits
//! only [`WorkloadNamespace::Runtime`]: a spec asking for anything else is
//! refused at admission, by name, rather than run in the runtime's namespaces
//! under a receipt that says otherwise. The only setup this runtime can record
//! is therefore [`NamespaceSetup::Runtime`], and it is read off an
//! [`AdmittedNamespace`], which only `admit` mints.

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use nucleus_ci_verdict::execution::NamespaceSetup;

/// Namespace placement requested for the workload.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkloadNamespace {
    /// Use the runtime's existing namespaces, with ordinary workload confinement.
    Runtime {},
    /// Fresh user/network namespaces with explicitly selected loopback state.
    /// Not admitted by this runtime: see [`WorkloadNamespace::admit`].
    PrivateUserNetwork {
        /// Identity inside the new user namespace; outer identity is the
        /// runtime's resolved workload UID.
        inner_uid: u32,
        /// Whether to raise the otherwise-down loopback interface.
        loopback: bool,
    },
}

/// The request this runtime cannot enforce, refused by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error(
    "workload namespace {requested:?} is refused: this runtime performs no trusted namespace \
     setup, so it admits only `runtime` placement"
)]
pub struct NamespaceRefused {
    /// What the spec asked for.
    pub requested: WorkloadNamespace,
}

/// A namespace request this runtime admitted. The private field means only
/// [`WorkloadNamespace::admit`] produces one (ADR 0007 C), so a recorded
/// [`NamespaceSetup`] is always one the runtime decided, never one a caller
/// asserted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct AdmittedNamespace {
    setup: NamespaceSetup,
}

impl AdmittedNamespace {
    /// The setup this launch performs, and the only value a receipt may record.
    pub fn setup(self) -> NamespaceSetup {
        self.setup
    }
}

impl WorkloadNamespace {
    /// The one admission decider. Exhaustive, no `_` arm (ADR 0007 B): a new
    /// variant is a compile error here until someone decides whether this
    /// runtime can enforce it.
    pub fn admit(self) -> Result<AdmittedNamespace, NamespaceRefused> {
        match self {
            Self::Runtime {} => Ok(AdmittedNamespace {
                setup: NamespaceSetup::Runtime {},
            }),
            Self::PrivateUserNetwork {
                inner_uid: _,
                loopback: _,
            } => Err(NamespaceRefused { requested: self }),
        }
    }

    /// The setup a relying party should expect a runtime that ENFORCES this
    /// request to record. A description, not a witness: it does not establish
    /// that any setup ran, and this runtime refuses every request whose
    /// expectation is not [`NamespaceSetup::Runtime`].
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

    #[test]
    fn only_runtime_placement_is_admitted_and_it_records_runtime() {
        assert_eq!(
            WorkloadNamespace::Runtime {}.admit().unwrap().setup(),
            NamespaceSetup::Runtime {}
        );
        for (inner_uid, loopback) in [(0, false), (0, true), (1000, true), (u32::MAX, false)] {
            let requested = WorkloadNamespace::PrivateUserNetwork {
                inner_uid,
                loopback,
            };
            assert_eq!(
                requested.admit().unwrap_err(),
                NamespaceRefused { requested }
            );
        }
    }
}
