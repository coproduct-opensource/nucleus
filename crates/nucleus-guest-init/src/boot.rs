//! The guest boot as a typestate: `Booting → Mounted → Provisioned → Sealed`,
//! and `exec` only from `Sealed` (#2589).
//!
//! `run()` used to fetch every secret over vsock, then `remount_root_ro`, then
//! `exec_proxy`, with the ordering enforced by nothing but the order of the
//! lines. Reorder them — move the remount after the exec, or forget it — and
//! the workload starts on a writable rootfs with no compiler, test or gate
//! noticing. Here the order is the type: [`Boot<Sealed>`] is the only state
//! with an `exec`, it is only produced by [`Boot::<Provisioned>::seal`], which
//! is the remount, and `Provisioned` is only produced from `Mounted`. A boot
//! that skips a step does not compile (see the `compile_fail` doctests in
//! `lib.rs`).
//!
//! Two failure policies live here too, because they are the same kind of
//! claim ("boot does not proceed on a broken base"):
//!   * mounts are classified **load-bearing** or optional; a load-bearing
//!     mount that fails aborts the boot with a named error instead of an
//!     `eprintln!` the kernel scrolls past;
//!   * the boot never falls back to a shell, and its error reaches PID 1's
//!     exit status.

use std::marker::PhantomData;

/// Errors that stop a boot. Each names what failed, so the guest console (the
/// only place PID 1 can speak) says which invariant broke rather than which
/// syscall.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootError {
    /// A load-bearing mount failed. The rootfs is not a place a workload can
    /// run without it.
    LoadBearingMountFailed {
        target: &'static str,
        fstype: &'static str,
        error: String,
    },
    /// A directory init needs could not be created.
    Dir { path: String, error: String },
    /// No pod spec at either location. There is no shell fallback: a guest
    /// with nothing to run has nothing to do, and a shell as PID 1 would be
    /// an unmediated workload.
    PodSpecMissing { primary: String, fallback: String },
    /// `remount / read-only` failed: refusing to start the workload rather
    /// than run it on a writable rootfs.
    SealFailed(String),
}

impl std::fmt::Display for BootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BootError::LoadBearingMountFailed {
                target,
                fstype,
                error,
            } => write!(
                f,
                "load-bearing mount {target} ({fstype}) failed: {error} — boot aborted"
            ),
            BootError::Dir { path, error } => write!(f, "create {path}: {error}"),
            BootError::PodSpecMissing { primary, fallback } => write!(
                f,
                "missing pod spec (expected {primary} or {fallback}) — refusing to boot: there is no workload to mediate and a shell as PID 1 would be an unmediated one"
            ),
            BootError::SealFailed(err) => write!(
                f,
                "remount / read-only failed: {err} — refusing to start the workload rather than run it on a writable rootfs"
            ),
        }
    }
}

impl std::error::Error for BootError {}

/// Marker: nothing mounted yet.
pub struct Booting;
/// Marker: every load-bearing mount is in place.
pub struct Mounted;
/// Marker: identity, secrets and the child environment are collected.
pub struct Provisioned;
/// Marker: the rootfs is read-only. The only state that can `exec`.
pub struct Sealed;

/// One guest mount and its policy. `load_bearing` decides what a failure
/// means: `true` aborts the boot, `false` logs and continues (a read-only or
/// absent optional volume is a legitimate guest — `workload.rs` allows a
/// read-only `/work`).
#[derive(Debug, Clone, Copy)]
pub struct MountSpec {
    pub source: &'static str,
    pub target: &'static str,
    pub fstype: &'static str,
    pub load_bearing: bool,
}

/// The outcome of one mount attempt, reported by the platform layer.
pub type MountResult = Result<(), String>;

/// The boot, parameterised by how far it has got. Consumed by every
/// transition, so a state cannot be reused after it has been advanced.
pub struct Boot<S> {
    /// Names of the mounts that failed but were optional — carried forward so
    /// the boot report can say what is missing.
    pub optional_mount_failures: Vec<&'static str>,
    _state: PhantomData<S>,
}

// By hand, not derived: a derive would demand `S: Debug` of the marker
// types, and the markers carry no data to print.
impl<S> std::fmt::Debug for Boot<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Boot")
            .field("state", &std::any::type_name::<S>())
            .field("optional_mount_failures", &self.optional_mount_failures)
            .finish()
    }
}

impl Boot<Booting> {
    /// A boot starts here and nowhere else.
    pub fn start() -> Self {
        Boot {
            optional_mount_failures: Vec::new(),
            _state: PhantomData,
        }
    }

    /// Mount everything in `mounts` through `mount_one` (the platform
    /// `mount(2)`, injected so the policy is testable on any host). A failed
    /// load-bearing mount is the boot's error; a failed optional mount is
    /// recorded and the boot goes on.
    pub fn mount_all(
        mut self,
        mounts: &[MountSpec],
        mut mount_one: impl FnMut(&MountSpec) -> MountResult,
    ) -> Result<Boot<Mounted>, BootError> {
        for m in mounts {
            match mount_one(m) {
                Ok(()) => {}
                Err(error) if m.load_bearing => {
                    return Err(BootError::LoadBearingMountFailed {
                        target: m.target,
                        fstype: m.fstype,
                        error,
                    });
                }
                Err(_) => self.optional_mount_failures.push(m.target),
            }
        }
        Ok(Boot {
            optional_mount_failures: self.optional_mount_failures,
            _state: PhantomData,
        })
    }
}

impl Boot<Mounted> {
    /// Identity, secrets and the child environment have been collected. The
    /// caller does that work between `mount_all` and here; this transition
    /// records that it happened before sealing, which is the order the
    /// workload API needs (secrets are read into memory, never onto the
    /// soon-to-be read-only rootfs).
    pub fn provisioned(self) -> Boot<Provisioned> {
        Boot {
            optional_mount_failures: self.optional_mount_failures,
            _state: PhantomData,
        }
    }
}

impl Boot<Provisioned> {
    /// Seal the rootfs read-only through `remount_ro` (the platform remount,
    /// injected). This is the only way to obtain a [`Boot<Sealed>`], hence
    /// the only way to `exec`.
    pub fn seal(
        self,
        remount_ro: impl FnOnce() -> Result<(), String>,
    ) -> Result<Boot<Sealed>, BootError> {
        remount_ro().map_err(BootError::SealFailed)?;
        Ok(Boot {
            optional_mount_failures: self.optional_mount_failures,
            _state: PhantomData,
        })
    }
}

impl Boot<Sealed> {
    /// Hand the sealed boot to the workload launcher. `launch` is the platform
    /// `exec(2)` (it does not return on success); it receives the proof that
    /// the rootfs was sealed first — this method's existence on `Sealed`
    /// alone. Returns the launcher's error if `exec` itself fails.
    pub fn exec<T>(self, launch: impl FnOnce(SealedProof) -> T) -> T {
        launch(SealedProof { _priv: () })
    }
}

/// A token that only [`Boot::<Sealed>::exec`] can mint: the launcher demands
/// it, so nothing outside this module can call the launcher first.
pub struct SealedProof {
    _priv: (),
}

/// Choose the pod spec: the primary path, else the fallback (copied into
/// place when possible), else a named error. Never a shell.
pub fn resolve_pod_spec(
    primary: &str,
    fallback: &str,
    exists: impl Fn(&str) -> bool,
    copy: impl FnOnce(&str, &str) -> bool,
) -> Result<String, BootError> {
    if exists(primary) {
        return Ok(primary.to_string());
    }
    if exists(fallback) {
        if copy(fallback, primary) {
            return Ok(primary.to_string());
        }
        return Ok(fallback.to_string());
    }
    Err(BootError::PodSpecMissing {
        primary: primary.to_string(),
        fallback: fallback.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LB: MountSpec = MountSpec {
        source: "proc",
        target: "/proc",
        fstype: "proc",
        load_bearing: true,
    };
    const OPT: MountSpec = MountSpec {
        source: "/dev/vdb",
        target: "/work",
        fstype: "ext4",
        load_bearing: false,
    };

    /// A failed load-bearing mount aborts the boot with a NAMED error — the
    /// old `mount_fs` printed and continued for every mount.
    #[test]
    fn load_bearing_mount_failure_aborts_with_a_named_error() {
        let err = Boot::start()
            .mount_all(&[LB, OPT], |m| {
                if m.target == "/proc" {
                    Err("EPERM".into())
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert_eq!(
            err,
            BootError::LoadBearingMountFailed {
                target: "/proc",
                fstype: "proc",
                error: "EPERM".into()
            }
        );
        assert!(
            err.to_string()
                .contains("load-bearing mount /proc (proc) failed")
        );
    }

    /// An optional mount may fail; the boot records it and continues.
    #[test]
    fn optional_mount_failure_is_recorded_not_fatal() {
        let boot = Boot::start()
            .mount_all(&[LB, OPT], |m| {
                if m.load_bearing {
                    Ok(())
                } else {
                    Err("no /dev/vdb".into())
                }
            })
            .expect("optional failure must not abort");
        assert_eq!(boot.optional_mount_failures, vec!["/work"]);
    }

    /// The seal is the remount; a failed remount never yields `Sealed`.
    #[test]
    fn seal_failure_never_yields_sealed() {
        let boot = Boot::start()
            .mount_all(&[LB], |_| Ok(()))
            .unwrap()
            .provisioned();
        let err = boot.seal(|| Err("EBUSY".into())).unwrap_err();
        assert_eq!(err, BootError::SealFailed("EBUSY".into()));
    }

    /// The full path: exec receives the proof only after a successful seal,
    /// and the launcher observes the remount happened first.
    #[test]
    fn exec_runs_only_after_the_remount() {
        let remounted = std::cell::Cell::new(false);
        let launched_after_remount = Boot::start()
            .mount_all(&[LB], |_| Ok(()))
            .unwrap()
            .provisioned()
            .seal(|| {
                remounted.set(true);
                Ok(())
            })
            .unwrap()
            .exec(|_proof: SealedProof| remounted.get());
        assert!(launched_after_remount);
    }

    /// No shell fallback: a missing spec is an error that names both paths.
    #[test]
    fn missing_spec_is_a_named_error_not_a_shell() {
        let err = resolve_pod_spec(
            "/etc/nucleus/pod.yaml",
            "/pod.yaml",
            |_| false,
            |_, _| false,
        )
        .unwrap_err();
        assert!(matches!(err, BootError::PodSpecMissing { .. }));
        assert!(err.to_string().contains("/etc/nucleus/pod.yaml"));
        assert!(err.to_string().contains("shell as PID 1"));
    }

    /// The fallback is copied into place when it can be, else used in place.
    #[test]
    fn fallback_spec_is_copied_into_place_when_possible() {
        let p = "/etc/nucleus/pod.yaml";
        let f = "/pod.yaml";
        assert_eq!(resolve_pod_spec(p, f, |x| x == f, |_, _| true).unwrap(), p);
        assert_eq!(resolve_pod_spec(p, f, |x| x == f, |_, _| false).unwrap(), f);
        assert_eq!(resolve_pod_spec(p, f, |x| x == p, |_, _| false).unwrap(), p);
    }
}
