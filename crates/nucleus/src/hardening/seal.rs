//! The runtime's seal against its own children (#3461): non-dumpable,
//! confirmed by the kernel.

/// What the runtime did to keep its own children out of it (#3461).
///
/// A child that shares the runtime's uid (the declared bare tier, or a
/// `Restricted` child of a non-root runtime) can open
/// `/proc/<runtime>/environ`, `mem` and `fd/*`. [`seal_runtime`] makes the
/// process non-dumpable, so the kernel refuses those files and `ptrace` to
/// every process without `CAP_SYS_PTRACE`. (Descriptors are the spawn's
/// half: every posture on Linux, the bare tier included, marks those above
/// stdio close-on-exec in the child.)
///
/// Evidence (ADR 0007 C-1): [`Self::environment`] answers
/// [`EnvironmentReach::ClosedToSameUid`] only for a value [`seal_runtime`]
/// minted after the kernel confirmed the seal. [`Self::unsealed`] claims
/// nothing, so a caller can always hold the weaker value.
#[derive(Debug)]
pub struct RuntimeSeal {
    /// True only when the kernel confirmed the process non-dumpable.
    sealed: bool,
}

/// Whether a process at the runtime's own uid can read the runtime's
/// environment and memory. A process at another non-root uid never can.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvironmentReach {
    /// The runtime is non-dumpable: `/proc/<pid>/environ` and `mem` refuse
    /// a same-uid process.
    ClosedToSameUid,
    /// Nothing keeps a same-uid process out (no seal, or a platform where
    /// the environment of a same-uid process is readable regardless).
    OpenToSameUid,
}

impl RuntimeSeal {
    /// A value that claims no seal: what a platform without one holds.
    #[must_use]
    pub fn unsealed() -> Self {
        Self { sealed: false }
    }

    /// What a same-uid child can read of this process.
    #[must_use]
    pub fn environment(&self) -> EnvironmentReach {
        if self.sealed {
            EnvironmentReach::ClosedToSameUid
        } else {
            EnvironmentReach::OpenToSameUid
        }
    }
}

/// Seal this process against its own children; see [`RuntimeSeal`]. Call it
/// first, before the process reads a secret or spawns anything.
///
/// # Errors
/// On Linux, the kernel's errno when it refused, or an
/// [`std::io::ErrorKind::Other`] error when the process still reads as
/// dumpable afterwards. Off Linux nothing is attempted and the answer is
/// [`RuntimeSeal::unsealed`].
pub fn seal_runtime() -> std::io::Result<RuntimeSeal> {
    super::imp::seal_self().map(|sealed| RuntimeSeal { sealed })
}
