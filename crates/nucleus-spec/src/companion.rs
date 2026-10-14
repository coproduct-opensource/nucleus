//! A companion process beside the workload ([`crate::WorkloadSpec::companion`]).
use serde::{Deserialize, Serialize};

/// A process the runtime starts beside the workload, under a uid that is
/// neither the runtime's nor the workload's.
///
/// # What it is for
///
/// Privilege separation INSIDE the workload. A workload that runs untrusted
/// commands (an agent's shell tool, say) and also holds the files and the door
/// those commands must not touch has no way, in a guest without user
/// namespaces and under `no_new_privs`, to run them as anyone else. The
/// runtime is the one process that can start a child under another uid, so the
/// spec asks it to: the companion runs under the same confinement as the
/// workload, is never admitted to the workload door (the door admits exactly
/// the workload's uid), is not handed the work dir, and gets no runtime
/// variables. It lives exactly as long as the workload. What the two say to
/// each other is theirs; the runtime only starts it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CompanionSpec {
    /// Executable to run, resolved inside the guest.
    pub command: String,
    /// Arguments, passed through verbatim.
    #[serde(default)]
    pub args: Vec<String>,
    /// Extra environment. No runtime variable (door, egress, identity) is added.
    #[serde(default)]
    pub env: std::collections::BTreeMap<String, String>,
    /// The companion's uid: required, and refused if it is the runtime's, the
    /// workload's, or root.
    pub uid: u32,
}
