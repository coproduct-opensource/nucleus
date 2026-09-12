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
    /// The host supplied a spec and it could not be written. NOT a fallback to
    /// the baked spec: the host believes it dispatched a different job, and
    /// running the image's own command while it thinks so is the two of them
    /// disagreeing about what ran.
    PodSpecUnwritable { path: String },
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
            BootError::PodSpecUnwritable { path } => write!(
                f,
                "the host supplied a pod spec and {path} could not be written — refusing to boot: running this image's own command while the host believes it dispatched another is the two of them disagreeing about what ran"
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
/// Write the spec the HOST supplied where [`resolve_pod_spec`] will find it.
///
/// # Why the host's answer wins
///
/// The command a pod runs is baked into its rootfs today, so every clone
/// restored from a snapshot inherits one pod's command — the defect
/// `WorkloadApiCommand::FetchPodSpec` documents, and the reason a snapshot base
/// is per-job rather than per-toolchain. A base that boots to the barrier
/// having asked for nothing can be restored for any job.
///
/// # Why a failed write is an error and not a fallback
///
/// If the host sent a spec and it could not be stored, the guest must NOT
/// quietly run the one in its image. Those are different jobs, and the host
/// believes it dispatched the first. Falling back would be "I could not look"
/// reported as "I looked and it was fine" (ADR 0007 A-2) with a command
/// attached.
///
/// `None` — the host had nothing to say — is not a failure: that is every pod
/// today, and it keeps its baked spec.
pub fn place_host_spec(
    primary: &str,
    fetched: Option<&str>,
    write: impl FnOnce(&str, &str) -> bool,
) -> Result<bool, BootError> {
    let Some(spec) = fetched else {
        return Ok(false);
    };
    if write(primary, spec) {
        Ok(true)
    } else {
        Err(BootError::PodSpecUnwritable {
            path: primary.to_string(),
        })
    }
}

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

#[cfg(test)]
mod host_spec_tests {
    use super::*;

    /// The host's spec is written where `resolve_pod_spec` looks, so the two
    /// compose: place, then resolve.
    #[test]
    fn a_host_supplied_spec_is_placed_and_then_resolved() {
        let mut written: Option<(String, String)> = None;
        let placed = place_host_spec("/etc/nucleus/pod.yaml", Some("cmd: build"), |p, body| {
            written = Some((p.to_string(), body.to_string()));
            true
        })
        .expect("placed");
        assert!(placed);
        assert_eq!(
            written,
            Some(("/etc/nucleus/pod.yaml".into(), "cmd: build".into()))
        );
        // Now the primary exists, so resolution finds it and never consults the
        // baked fallback.
        let got = resolve_pod_spec(
            "/etc/nucleus/pod.yaml",
            "/pod.yaml",
            |p| p == "/etc/nucleus/pod.yaml",
            |_, _| panic!("must not copy the baked spec over the host's"),
        )
        .expect("resolved");
        assert_eq!(got, "/etc/nucleus/pod.yaml");
    }

    /// **No host spec is not an error.** That is every pod today: the host says
    /// nothing and the image's own spec stands.
    #[test]
    fn no_host_spec_leaves_the_baked_one_alone() {
        let placed = place_host_spec("/etc/nucleus/pod.yaml", None, |_, _| {
            panic!("nothing to write")
        })
        .expect("not an error");
        assert!(!placed);
    }

    /// **A failed write is an error, never a fallback.** The host believes it
    /// dispatched one job; running the image's is the two disagreeing about
    /// what ran. "I could not look" is never "I looked and it was fine".
    #[test]
    fn a_spec_the_host_sent_but_we_could_not_store_aborts_the_boot() {
        let err = place_host_spec("/etc/nucleus/pod.yaml", Some("cmd: build"), |_, _| false)
            .expect_err("must not fall back");
        assert!(
            matches!(err, BootError::PodSpecUnwritable { ref path } if path == "/etc/nucleus/pod.yaml"),
            "{err:?}"
        );
        // And it says why, because a guest that aborts silently is a boot
        // nobody can diagnose from the console.
        assert!(
            format!("{err}").contains("disagreeing about what ran"),
            "{err}"
        );
    }
}
