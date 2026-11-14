use serde::{Deserialize, Serialize};

/// Namespace setup reported by a protected launch. This data alone is not
/// evidence: the runtime's sealed hook record and signed execution claim
/// establish its provenance. Missing legacy evidence never means runtime setup.
///
/// It describes the workload's USER and NETWORK namespaces only. Whether the
/// workload has its own PID namespace is not a field here: a guest workload
/// has one whatever this says, and the launch receipt's `pids=` (in the
/// claim's `launch_hash`) records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum NamespaceSetup {
    /// Legacy evidence did not record namespace setup.
    Unrecorded {},
    /// Retain the runtime's user and network namespaces, with ordinary workload
    /// confinement.
    Runtime {},
    /// Empty network namespace for an isolated host service.
    PrivateNetwork {},
    /// Fresh user/network namespaces with stated loopback and exactly one mapped ID.
    PrivateUserNetwork {
        outer_uid: u32,
        inner_uid: u32,
        loopback: bool,
    },
}

impl NamespaceSetup {
    pub fn not_recorded() -> Self {
        Self::Unrecorded {}
    }

    /// Stable spelling for the launch inventory commitment.
    #[must_use]
    pub fn canonical(self) -> String {
        match self {
            Self::Unrecorded {} => "unrecorded".into(),
            Self::Runtime {} => "runtime".into(),
            Self::PrivateNetwork {} => "private_network".into(),
            Self::PrivateUserNetwork {
                outer_uid,
                inner_uid,
                loopback,
            } => format!("private_user_network:{outer_uid}:{inner_uid}:{loopback}"),
        }
    }
}
