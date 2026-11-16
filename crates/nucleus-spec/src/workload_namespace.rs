//! The namespace placement a workload requests, and what a runtime admits.
//!
//! # What is published, and what is admitted where
//!
//! A spec can name [`WorkloadNamespace::PrivateUserNetwork`], and an execution
//! claim (`nucleus.execution.v2`) carries the [`NamespaceSetup`] the runtime
//! recorded, which the verifier binds against an independent expectation.
//!
//! [`WorkloadNamespace::admit`] is the one decider. It takes what the deciding
//! site knows about its runtime, [`NamespaceEnforcement`], and the outer uid
//! the spec states. A private placement is admitted only where the runtime
//! performs the trusted setup that makes it true: a root guest runtime whose
//! workload hook makes a PID namespace and, inside it, after the uid drop, a
//! fresh user and network namespace mapping exactly `inner_uid` to the outer
//! uid (`nucleus::hardening`, `docs/findings/workload-user-network-namespace.md`).
//! Everywhere else it is refused by name, never run in the runtime's
//! namespaces under a receipt that says otherwise.
//!
//! The setup a receipt records is read off an [`AdmittedNamespace`], which only
//! `admit` mints, as the expectation; the runtime's hook record must then
//! equal it before anything is signed.

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use nucleus_ci_verdict::execution::NamespaceSetup;

/// Namespace placement requested for the workload.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkloadNamespace {
    /// Use the runtime's user and network namespaces, with ordinary workload
    /// confinement.
    Runtime {},
    /// Fresh user/network namespaces with explicitly selected loopback state.
    /// Admitted only where [`NamespaceEnforcement::PrivateUserNetwork`] holds:
    /// see [`WorkloadNamespace::admit`].
    PrivateUserNetwork {
        /// Identity inside the new user namespace; the outer identity is the
        /// spec's `workload.uid`, which must be stated.
        inner_uid: u32,
        /// Whether to raise the otherwise-down loopback interface.
        loopback: bool,
    },
}

/// Which namespace placements the deciding site's runtime can make true.
///
/// Two named cases, not a `bool` (ADR 0007 A), and no `Default` (B-1). It is
/// what a site knows, not evidence: the runtime's hook record is the evidence,
/// and it must equal the admitted expectation before a claim is signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceEnforcement {
    /// No trusted user+network setup here: only `runtime` placement.
    RuntimeOnly,
    /// A root guest runtime whose workload hook makes the workload's own PID
    /// namespace and, inside it, after the uid drop, a fresh user and network
    /// namespace with exactly one mapped id.
    PrivateUserNetwork,
}

/// A namespace request this site refuses, by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum NamespaceRefused {
    /// The runtime here performs no trusted user+network setup.
    #[error(
        "workload namespace {requested:?} is refused: this runtime cannot set up a private user \
         and network namespace for its workload, so it admits only `runtime` placement"
    )]
    NotEnforcedHere {
        /// What the spec asked for.
        requested: WorkloadNamespace,
    },
    /// A private placement whose outer uid the spec leaves to a default.
    #[error(
        "workload namespace {requested:?} is refused: a private user namespace maps `inner_uid` \
         to `workload.uid`, which must be stated, not defaulted"
    )]
    OuterUidUnstated {
        /// What the spec asked for.
        requested: WorkloadNamespace,
    },
    /// A mapping onto real root, or onto the kernel's reserved id.
    #[error(
        "workload namespace {requested:?} with workload.uid {outer_uid} is refused: the outer uid \
         must be neither 0 nor {max}, and the inner uid not {max}",
        max = u32::MAX
    )]
    Unmappable {
        /// What the spec asked for.
        requested: WorkloadNamespace,
        /// The spec's `workload.uid`.
        outer_uid: u32,
    },
}

/// A namespace request this runtime admitted. The private field means only
/// [`WorkloadNamespace::admit`] produces one (ADR 0007 C-1), so a recorded
/// expectation is always one the runtime decided, never one a caller asserted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct AdmittedNamespace {
    setup: NamespaceSetup,
}

impl AdmittedNamespace {
    /// The setup this launch must perform: what the runtime's hook record must
    /// equal before a claim is signed.
    pub fn setup(self) -> NamespaceSetup {
        self.setup
    }
}

impl WorkloadNamespace {
    /// The one admission decider. Exhaustive, no `_` arm (ADR 0007 B-3): a new
    /// variant or enforcement is a compile error here until someone decides it.
    ///
    /// `outer_uid` is the spec's `workload.uid`.
    ///
    /// # Errors
    /// [`NamespaceRefused`], naming why.
    pub fn admit(
        self,
        outer_uid: Option<u32>,
        enforcement: NamespaceEnforcement,
    ) -> Result<AdmittedNamespace, NamespaceRefused> {
        match (self, enforcement) {
            (Self::Runtime {}, NamespaceEnforcement::RuntimeOnly)
            | (Self::Runtime {}, NamespaceEnforcement::PrivateUserNetwork) => {
                Ok(AdmittedNamespace {
                    setup: NamespaceSetup::Runtime {},
                })
            }
            (
                Self::PrivateUserNetwork {
                    inner_uid: _,
                    loopback: _,
                },
                NamespaceEnforcement::RuntimeOnly,
            ) => Err(NamespaceRefused::NotEnforcedHere { requested: self }),
            (
                Self::PrivateUserNetwork {
                    inner_uid,
                    loopback: _,
                },
                NamespaceEnforcement::PrivateUserNetwork,
            ) => match outer_uid {
                None => Err(NamespaceRefused::OuterUidUnstated { requested: self }),
                Some(outer) if outer == 0 || outer == u32::MAX || inner_uid == u32::MAX => {
                    Err(NamespaceRefused::Unmappable {
                        requested: self,
                        outer_uid: outer,
                    })
                }
                Some(outer) => Ok(AdmittedNamespace {
                    setup: self.expected(outer),
                }),
            },
        }
    }

    /// The setup a relying party should expect a runtime that ENFORCES this
    /// request to record. A description, not a witness: it does not establish
    /// that any setup ran.
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

    const HERE: NamespaceEnforcement = NamespaceEnforcement::PrivateUserNetwork;
    const NOT_HERE: NamespaceEnforcement = NamespaceEnforcement::RuntimeOnly;

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

    /// Runtime placement is admitted everywhere and records `runtime`, with
    /// or without a stated uid.
    #[test]
    fn runtime_placement_is_admitted_everywhere_and_records_runtime() {
        for enforcement in [HERE, NOT_HERE] {
            for outer in [None, Some(65534), Some(0)] {
                assert_eq!(
                    WorkloadNamespace::Runtime {}
                        .admit(outer, enforcement)
                        .unwrap()
                        .setup(),
                    NamespaceSetup::Runtime {}
                );
            }
        }
    }

    /// Where the runtime cannot set it up, a private placement is refused by
    /// name, whatever else the spec says.
    #[test]
    fn a_private_placement_is_refused_where_it_is_not_enforced() {
        for (inner_uid, loopback) in [(0, false), (0, true), (1000, true), (u32::MAX, false)] {
            let requested = WorkloadNamespace::PrivateUserNetwork {
                inner_uid,
                loopback,
            };
            for outer in [None, Some(65534)] {
                assert_eq!(
                    requested.admit(outer, NOT_HERE).unwrap_err(),
                    NamespaceRefused::NotEnforcedHere { requested }
                );
            }
        }
    }

    /// Where it is enforced, a private placement is admitted with the spec's
    /// own outer uid, and the expectation is exactly the one mapping.
    #[test]
    fn a_private_placement_is_admitted_where_enforced_and_records_the_one_mapping() {
        for (inner_uid, loopback) in [(0, false), (0, true), (1001, false), (1001, true)] {
            let requested = WorkloadNamespace::PrivateUserNetwork {
                inner_uid,
                loopback,
            };
            assert_eq!(
                requested.admit(Some(65534), HERE).unwrap().setup(),
                NamespaceSetup::PrivateUserNetwork {
                    outer_uid: 65534,
                    inner_uid,
                    loopback
                }
            );
        }
    }

    /// A mapping nobody can check from the spec (the outer uid left to a
    /// default), onto real root, or onto the kernel's reserved id, is refused.
    #[test]
    fn an_unstated_or_unmappable_identity_is_refused() {
        let requested = WorkloadNamespace::PrivateUserNetwork {
            inner_uid: 0,
            loopback: true,
        };
        assert_eq!(
            requested.admit(None, HERE).unwrap_err(),
            NamespaceRefused::OuterUidUnstated { requested }
        );
        for outer in [0, u32::MAX] {
            assert_eq!(
                requested.admit(Some(outer), HERE).unwrap_err(),
                NamespaceRefused::Unmappable {
                    requested,
                    outer_uid: outer
                }
            );
        }
        let reserved = WorkloadNamespace::PrivateUserNetwork {
            inner_uid: u32::MAX,
            loopback: false,
        };
        assert_eq!(
            reserved.admit(Some(65534), HERE).unwrap_err(),
            NamespaceRefused::Unmappable {
                requested: reserved,
                outer_uid: 65534
            }
        );
    }
}
