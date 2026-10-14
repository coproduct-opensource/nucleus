//! A read-only workspace: the rule and the record (#2907).
//!
//! What the module docs of `hardening` describe as "a read-only workspace":
//! the rule ([`WorkspaceWrites::of`]), the receipt's value ([`WorkspaceHold`])
//! and the decided layer `apply` installs. The decider itself is
//! `ChildConfinement::workspace_hold`; the layer is `landlock::write_scope`.

use std::path::Path;

/// Whether a pod's lattice lets its children write its workspace (#2907),
/// and where that workspace is.
///
/// The `run_bash` children of a pod whose policy says `write_files: never`
/// and `edit_files: never` used to write the workspace freely: the tool
/// proxy refused the agent's own write tool, and nothing held its children.
/// Seccomp cannot see paths. The rule is a Landlock layer
/// (`hardening/landlock.rs`, the write layer) that refuses every write right
/// except to the runtime's scratch.
///
/// No `Default` (ADR 0007 B-1): [`Self::of`] derives it from a lattice, or a
/// caller with no pod (a host service) names [`Self::Writable`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceWrites {
    /// The pod may write files (`write_files` or `edit_files` is not
    /// `never`): its children get no write layer.
    Writable,
    /// `write_files` and `edit_files` are both `never`: no child writes
    /// anything under `workspace`, except the runtime's scratch.
    ReadOnly {
        /// The pod's workspace root (`/work` in a guest).
        workspace: std::path::PathBuf,
    },
}

impl WorkspaceWrites {
    /// The ONE rule (ADR 0007 G-1): read-only exactly when the lattice
    /// refuses both ways of writing a file. Pass the lattice the executor
    /// runs, the normalized one.
    #[must_use]
    pub fn of(lattice: &portcullis::PermissionLattice, workspace: &Path) -> Self {
        use portcullis::CapabilityLevel;
        let caps = &lattice.capabilities;
        if caps.write_files == CapabilityLevel::Never && caps.edit_files == CapabilityLevel::Never {
            Self::ReadOnly {
                workspace: workspace.to_path_buf(),
            }
        } else {
            Self::Writable
        }
    }
}

/// How a child's workspace is held, as its launch receipt states it (#2907).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum WorkspaceHold {
    /// No write layer: the pod may write its workspace.
    Writable,
    /// The Landlock write layer, at this ABI: the child writes only the
    /// runtime's scratch.
    ReadOnly {
        /// The kernel's Landlock ABI.
        abi: u32,
    },
}

impl WorkspaceHold {
    /// The canonical spelling a receipt's hashed preimage carries.
    #[must_use]
    pub fn canonical(&self) -> String {
        match self {
            Self::Writable => "writable".to_string(),
            Self::ReadOnly { abi } => format!("read_only:{abi}"),
        }
    }
}

/// The write layer as [`ChildConfinement::apply`] installs it: decided, with
/// the workspace it holds. Two named cases, not an `Option` (B-2).
#[derive(Debug, Clone, Copy)]
pub(super) enum WriteLayer<'a> {
    None,
    ReadOnly { abi: u32, workspace: &'a Path },
}

impl WriteLayer<'_> {
    pub(super) fn hold(self) -> WorkspaceHold {
        match self {
            Self::None => WorkspaceHold::Writable,
            Self::ReadOnly { abi, workspace: _ } => WorkspaceHold::ReadOnly { abi },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::ContainmentMode;
    use crate::error::NucleusError;
    use crate::hardening::{
        ChildConfinement, LandlockSupport, LandlockWaiver, MIN_LANDLOCK_ABI, RlimitPolicy,
        SpawnHardening, Unhardened, UnsandboxedOptIn,
    };
    use portcullis::SeccompPolicy;

    const NO: LandlockWaiver = LandlockWaiver::Absent;

    /// Every posture a pod child can be decided into, on `kernel`, with the
    /// operator's Landlock waiver given wherever it changes anything (#2907).
    fn every_child_posture(kernel: LandlockSupport) -> Vec<(&'static str, ChildConfinement)> {
        let waived = LandlockWaiver::Explicit;
        let mut out = vec![
            (
                "MicroVM (root guest)",
                ChildConfinement::decide(
                    ContainmentMode::MicroVM,
                    0,
                    UnsandboxedOptIn::Absent,
                    kernel,
                    waived,
                )
                .unwrap(),
            ),
            (
                "root Unsandboxed (root container, root local node)",
                ChildConfinement::decide(
                    ContainmentMode::Unsandboxed,
                    0,
                    UnsandboxedOptIn::Absent,
                    kernel,
                    waived,
                )
                .unwrap(),
            ),
            (
                "non-root bare tier (local driver, nucleus run --local)",
                ChildConfinement::decide(
                    ContainmentMode::Unsandboxed,
                    1000,
                    UnsandboxedOptIn::Explicit,
                    kernel,
                    waived,
                )
                .unwrap(),
            ),
            (
                "non-root HostHardened",
                ChildConfinement::decide(
                    ContainmentMode::HostHardened,
                    1000,
                    UnsandboxedOptIn::Absent,
                    kernel,
                    waived,
                )
                .unwrap(),
            ),
        ];
        out.push((
            "MicroVM workload",
            ChildConfinement::decide_workload(
                ContainmentMode::MicroVM,
                None,
                0,
                UnsandboxedOptIn::Absent,
                kernel,
                waived,
            )
            .unwrap(),
        ));
        out
    }

    fn read_only() -> WorkspaceWrites {
        WorkspaceWrites::ReadOnly {
            workspace: std::path::PathBuf::from("/work"),
        }
    }

    /// THE rule (#2907): a pod's workspace is read-only to its children
    /// exactly when its lattice refuses both ways of writing a file. Red if
    /// either `never` alone makes it read-only, or if both do not.
    #[test]
    fn a_workspace_is_read_only_exactly_when_write_and_edit_are_never() {
        use portcullis::CapabilityLevel::{Always, LowRisk, Never};
        let ws = Path::new("/work");
        for (write, edit, expected) in [
            (Never, Never, read_only()),
            (Never, LowRisk, WorkspaceWrites::Writable),
            (LowRisk, Never, WorkspaceWrites::Writable),
            (Always, Always, WorkspaceWrites::Writable),
        ] {
            let mut lattice = portcullis::PermissionLattice::permissive();
            lattice.capabilities.write_files = write;
            lattice.capabilities.edit_files = edit;
            assert_eq!(
                WorkspaceWrites::of(&lattice, ws),
                expected,
                "write_files {write:?}, edit_files {edit:?}"
            );
        }
        // The shipped profiles that say `never` twice are held read-only;
        // test-runner among them, which runs `cargo test`: its children write
        // the scratch, not the workspace (the profile says so).
        let registry = portcullis::profile::ProfileRegistry::canonical().unwrap();
        for name in ["test-runner", "read-only", "code-review", "triage-bot"] {
            let lattice = registry.resolve(name).unwrap().normalize();
            assert_eq!(WorkspaceWrites::of(&lattice, ws), read_only(), "{name}");
        }
        for name in ["codegen", "local-dev", "doc-editor"] {
            let lattice = registry.resolve(name).unwrap().normalize();
            assert_eq!(
                WorkspaceWrites::of(&lattice, ws),
                WorkspaceWrites::Writable,
                "{name}"
            );
        }
    }

    /// Wherever the kernel has Landlock, every posture holds a read-only
    /// workspace with the write layer, the bare tier included, and a writable
    /// one needs nothing. Red if any posture lets a read-only workspace
    /// through as writable.
    #[test]
    fn a_read_only_workspace_is_held_in_every_posture_on_a_landlock_kernel() {
        for kernel in [LandlockSupport::Abi(2), LandlockSupport::Abi(5)] {
            let abi = kernel.enforceable().unwrap();
            for (name, c) in every_child_posture(kernel) {
                assert_eq!(
                    c.workspace_hold(&read_only()).unwrap(),
                    WorkspaceHold::ReadOnly { abi },
                    "{name}"
                );
                assert_eq!(
                    c.workspace_hold(&WorkspaceWrites::Writable).unwrap(),
                    WorkspaceHold::Writable,
                    "{name}"
                );
            }
        }
    }

    /// Fail closed by name (#2907): where Landlock cannot be enforced (a
    /// kernel without it, below ABI 2, or not Linux), a read-only workspace
    /// refuses every posture, naming the workspace and what the kernel
    /// offered. The operator's Landlock waiver (given to every posture here)
    /// does not reach it. A writable workspace is unaffected. Red if any
    /// posture runs the child with its workspace writable.
    #[test]
    fn a_read_only_workspace_is_refused_by_name_without_landlock() {
        for kernel in [LandlockSupport::Unavailable, LandlockSupport::Abi(1)] {
            for (name, c) in every_child_posture(kernel) {
                match c.workspace_hold(&read_only()) {
                    Err(NucleusError::WorkspaceReadOnlyUnenforceable {
                        workspace,
                        kernel: offered,
                        minimum,
                    }) => {
                        assert_eq!(workspace, "/work", "{name}");
                        assert_eq!(offered, kernel.to_string(), "{name}");
                        assert_eq!(minimum, MIN_LANDLOCK_ABI, "{name}");
                    }
                    other => panic!("{name} on {kernel}: {other:?}"),
                }
                assert!(
                    matches!(
                        c.preflight_filesystem(&read_only()),
                        Err(NucleusError::WorkspaceReadOnlyUnenforceable { .. })
                    ),
                    "{name}: the preflight names it"
                );
                assert_eq!(
                    c.workspace_hold(&WorkspaceWrites::Writable).unwrap(),
                    WorkspaceHold::Writable,
                    "{name}"
                );
            }
        }
        let rendered = NucleusError::WorkspaceReadOnlyUnenforceable {
            workspace: "/work".to_string(),
            kernel: LandlockSupport::Unavailable.to_string(),
            minimum: MIN_LANDLOCK_ABI,
        }
        .to_string();
        assert!(rendered.contains("write_files: never"), "{rendered}");
        assert!(rendered.contains("/work"), "{rendered}");
        // Actionable (owner decision 2026-10-14): what was refused and why,
        // the way to proceed, and that nothing runs unconfined instead.
        for needed in [
            "cannot enforce a read-only workspace",
            "--profile codegen",
            "Linux host with Landlock",
            "nothing will run unconfined",
        ] {
            assert!(rendered.contains(needed), "missing {needed:?}: {rendered}");
        }
    }

    /// The enforcement half of the refusal: `apply` without the preflight
    /// still fails the spawn, in every posture, the bare tier included. Red
    /// if a caller that skipped the preflight ran the child.
    #[cfg(unix)]
    #[test]
    fn apply_refuses_the_spawn_when_the_workspace_cannot_be_held() {
        let rlimits = RlimitPolicy::node_ceiling().at_ceiling();
        let derived = SeccompPolicy::derive(
            &portcullis::PermissionLattice::permissive(),
            portcullis::NetworkEgress::Declared,
        );
        for (name, c) in every_child_posture(LandlockSupport::Unavailable) {
            let mut cmd = std::process::Command::new("/bin/true");
            let got = c.apply(&mut cmd, rlimits, derived, &read_only());
            assert_eq!(
                got,
                SpawnHardening::Unhardened(Unhardened::Refused),
                "{name}"
            );
            assert_eq!(got.workspace_canonical(), "refused");
            // Refused before any uid is declared, so the hook alone decides.
            let err = cmd.status().expect_err("the hook refuses the spawn");
            assert_eq!(err.raw_os_error(), Some(libc::EOPNOTSUPP), "{name}");
        }
    }

    /// The receipt's spelling of the hold, read off what the hook installed.
    #[test]
    fn the_workspace_hold_spells_what_was_installed() {
        assert_eq!(WorkspaceHold::Writable.canonical(), "writable");
        assert_eq!(
            WorkspaceHold::ReadOnly { abi: 5 }.canonical(),
            "read_only:5"
        );
        assert_eq!(
            SpawnHardening::Unhardened(Unhardened::DeclaredBareTier).workspace_canonical(),
            "writable"
        );
        assert_eq!(
            SpawnHardening::Unhardened(Unhardened::BareTierWorkspaceReadOnly { abi: 3 })
                .workspace_canonical(),
            "read_only:3"
        );
    }

    /// On a Landlock kernel the bare tier's read-only workspace gets the
    /// write layer's own hook, and says so; a hardened posture records the
    /// hold in its evidence. Red if `apply` reports a writable workspace for
    /// a read-only one.
    #[cfg(target_os = "linux")]
    #[test]
    fn apply_reports_the_write_layer_it_installs() {
        let Some(abi) = LandlockSupport::probe().enforceable() else {
            eprintln!("SKIPPED: this kernel has no Landlock ABI >= 2");
            return;
        };
        let kernel = LandlockSupport::Abi(abi);
        // What `apply` reports is the decision; whether this host can compile
        // the layer for `/work` is the hook's, which refuses if it cannot.
        let writes = read_only();
        let rlimits = RlimitPolicy::node_ceiling().at_ceiling();
        let derived = SeccompPolicy::derive(
            &portcullis::PermissionLattice::permissive(),
            portcullis::NetworkEgress::Declared,
        );
        let bare = ChildConfinement::decide(
            ContainmentMode::Unsandboxed,
            1000,
            UnsandboxedOptIn::Explicit,
            kernel,
            NO,
        )
        .unwrap();
        assert_eq!(
            bare.apply(
                &mut std::process::Command::new("/bin/true"),
                rlimits,
                derived,
                &writes
            ),
            SpawnHardening::Unhardened(Unhardened::BareTierWorkspaceReadOnly { abi })
        );
        let restricted = ChildConfinement::decide(
            ContainmentMode::HostHardened,
            1000,
            UnsandboxedOptIn::Absent,
            kernel,
            NO,
        )
        .unwrap();
        match restricted.apply(
            &mut std::process::Command::new("/bin/true"),
            rlimits,
            derived,
            &writes,
        ) {
            SpawnHardening::Hardened(h) => {
                assert_eq!(h.workspace(), WorkspaceHold::ReadOnly { abi });
            }
            SpawnHardening::Unhardened(why) => panic!("{why:?}"),
        }
    }
}
