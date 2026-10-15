//! What a spawn's confinement hook did, as the launch receipt states it
//! (#2572, #2907): minted only by `ChildConfinement::apply`.

use portcullis::SeccompPolicy;

use super::{AppliedRlimits, PidNamespace, WorkspaceHold};

/// What a spawn's confinement hook does to the child, as its launch receipt
/// states it (#2572).
///
/// The hardened case carries a [`Hardened`], which has a private field and is
/// minted only by [`ChildConfinement::apply`](super::ChildConfinement::apply) when it installed the hook, so
/// the bare tier — or a platform with no hook — cannot claim it. Before this,
/// the receipt carried a `bool` the caller computed beside the spawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SpawnHardening {
    /// Inherited fds above 2 close-on-exec, `no_new_privs`, the rlimits,
    /// and the syscall filter when the posture has one.
    Hardened(Hardened),
    /// No hook: the child is a plain process, and why.
    Unhardened(Unhardened),
}

impl SpawnHardening {
    /// Whether the hook was installed.
    #[must_use]
    pub fn is_hardened(&self) -> bool {
        match self {
            Self::Hardened(_) => true,
            Self::Unhardened(_) => false,
        }
    }

    /// How the child's workspace is held, as the receipt's preimage spells
    /// it (#2907), read off what [`ChildConfinement::apply`](super::ChildConfinement::apply) installed: the
    /// one record of it. `refused` only for a spawn the hook fails, which
    /// never produces a receipt.
    #[must_use]
    pub fn workspace_canonical(&self) -> String {
        match self {
            Self::Hardened(h) => h.workspace.canonical(),
            Self::Unhardened(Unhardened::BareTierWorkspaceReadOnly { abi }) => {
                WorkspaceHold::ReadOnly { abi: *abi }.canonical()
            }
            Self::Unhardened(Unhardened::DeclaredBareTier | Unhardened::NoHookOnThisPlatform) => {
                WorkspaceHold::Writable.canonical()
            }
            Self::Unhardened(Unhardened::Refused) => "refused".to_string(),
        }
    }
}

/// The evidence that the confinement hook was installed, with which limits
/// and which syscall filter. Private fields: only [`ChildConfinement::apply`](super::ChildConfinement::apply)
/// mints one (ADR 0007 C-1, C-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Hardened {
    pub(super) rlimits: AppliedRlimits,
    pub(super) syscalls: InstalledFilter,
    /// How the hook holds the workspace (#2907).
    pub(super) workspace: WorkspaceHold,
    /// Whether the hook made the child a PID namespace (#3344).
    pub(super) pids: PidNamespace,
}

impl Hardened {
    /// How the hook holds the child's workspace (#2907).
    #[must_use]
    pub fn workspace(&self) -> WorkspaceHold {
        self.workspace
    }

    /// Whether the hook runs the child in its own PID namespace (#3344).
    #[must_use]
    pub fn pid_namespace(&self) -> PidNamespace {
        self.pids
    }

    /// The limits the hook sets.
    #[must_use]
    pub fn rlimits(&self) -> AppliedRlimits {
        self.rlimits
    }

    /// The syscall filter the hook installs.
    #[must_use]
    pub fn syscalls(&self) -> InstalledFilter {
        self.syscalls
    }
}

/// The syscall filter a hardened child runs under, as its launch receipt
/// states it (#2907): the ONE record of the pod's derived classes, written
/// where the hook that installs them reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum InstalledFilter {
    /// The workload denylist and, in the same program, the classes the pod's
    /// lattice denies.
    WorkloadDenylist {
        /// The derived classes, serialized as their names.
        derived: SeccompPolicy,
    },
    /// No filter: the declared bare tier's contract. The pod's derived
    /// classes are NOT applied, and this says so.
    Unfiltered,
}

impl InstalledFilter {
    /// The canonical spelling a receipt's hashed preimage carries.
    #[must_use]
    pub fn canonical(&self) -> String {
        match self {
            Self::WorkloadDenylist { derived } => format!("denylist+{}", derived.canonical()),
            Self::Unfiltered => "unfiltered".to_string(),
        }
    }
}

/// Why a spawn has no confinement hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Unhardened {
    /// The declared bare host tier (`ContainmentMode::Unsandboxed` on a
    /// non-root runtime, explicitly opted in).
    DeclaredBareTier,
    /// A posture without a syscall filter on a platform that has no hook
    /// (a root runtime's `Unsandboxed` child off Linux): the uid drop
    /// happens, nothing else does.
    NoHookOnThisPlatform,
    /// The declared bare host tier, with a read-only workspace (#2907): the
    /// hook sets `no_new_privs` and installs the Landlock write layer at this
    /// ABI, and nothing else. No fd closing, no rlimits, no syscall filter.
    BareTierWorkspaceReadOnly {
        /// The kernel's Landlock ABI.
        abi: u32,
    },
    /// The hook fails the spawn before exec: the pod's read-only workspace
    /// cannot be held here (#2907), or a subordinate-id child asked for its
    /// own PID namespace, which is not composed (#3344, Program C, C2). No
    /// child runs, so no receipt carries it.
    Refused,
}
