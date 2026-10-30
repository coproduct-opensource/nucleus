//! The launcher's read-only workspace bind, observed on a REAL confined child.
//!
//! The child is this test binary again, spawned through
//! `ChildConfinement::apply_with_namespaces` exactly as the tool-proxy spawns a
//! guest workload: MicroVM confinement, its own PID and mount namespaces, uid
//! 65534, Landlock and the workload seccomp filter. The parent asks for a bind
//! of a work-dir directory over an empty directory of a read-only filesystem
//! under `/data/work`, as a gate's step 0 does for nucleus's verifier SDK.
//!
//! Root Linux only, because only a root runtime can make the namespaces (a
//! guest's runtime is root). Elsewhere the test checks that the confinement is
//! refused rather than degraded, as `child_seccomp`'s namespace test does.
//! Run it as `sudo` on Linux, or as root in a VM (an Apple `container` with
//! `--cap-add ALL` works).

#![cfg(target_os = "linux")]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use nucleus::portcullis::{NetworkEgress, PermissionLattice, SeccompPolicy};
use nucleus::{
    ChildConfinement, ContainmentMode, LandlockWaiver, NamespaceRequest, NetworkNamespace,
    PidNamespace, UnsandboxedOptIn, WorkspaceBind,
};

const TARGET_ENV: &str = "NUCLEUS_WORKSPACE_BIND_TARGET";
const RESULT: &str = "WORKSPACE_BIND_RESULT ";

/// The child's entry point. A no-op when run as an ordinary test.
#[test]
fn child_entry() {
    let Ok(target) = std::env::var(TARGET_ENV) else {
        return;
    };
    let target = PathBuf::from(target);
    let marker = std::fs::read_to_string(target.join("marker"))
        .unwrap_or_else(|e| format!("unreadable:{}", e.raw_os_error().unwrap_or(-1)));
    let write = match std::fs::write(target.join("new"), b"x") {
        Ok(()) => "allowed".to_owned(),
        Err(e) => format!("errno={}", e.raw_os_error().unwrap_or(-1)),
    };
    // The bind's own line in this namespace's mount table: its options.
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    let options = mountinfo
        .lines()
        .find(|l| l.split(' ').nth(4) == Some(target.to_str().unwrap()))
        .and_then(|l| l.split(' ').nth(5))
        .unwrap_or("absent")
        .to_owned();
    let uid = std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .map_or_else(String::new, |v| {
            v.split_whitespace().next().unwrap_or("").to_owned()
        });
    let mut out = std::io::stdout().lock();
    let _ = writeln!(
        out,
        "{RESULT}marker={marker} write={write} options={options} uid={uid}"
    );
    let _ = out.flush();
    std::process::exit(0);
}

struct Cleanup(Vec<PathBuf>, Vec<PathBuf>);

impl Drop for Cleanup {
    fn drop(&mut self) {
        for m in self.1.iter().rev() {
            if let Ok(c) = std::ffi::CString::new(m.to_str().unwrap()) {
                // SAFETY: a NUL-terminated path; failure is ignored.
                unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) };
            }
        }
        for d in &self.0 {
            let _ = std::fs::remove_dir_all(d);
        }
    }
}

fn mount(src: &str, dst: &Path, fstype: &str, flags: libc::c_ulong) {
    let src = std::ffi::CString::new(src).unwrap();
    let dst_c = std::ffi::CString::new(dst.to_str().unwrap()).unwrap();
    let fstype = std::ffi::CString::new(fstype).unwrap();
    // SAFETY: NUL-terminated strings that outlive the call.
    let rc = unsafe {
        libc::mount(
            src.as_ptr(),
            dst_c.as_ptr(),
            fstype.as_ptr(),
            flags,
            std::ptr::null(),
        )
    };
    assert_eq!(
        rc,
        0,
        "mount {}: {}",
        dst.display(),
        std::io::Error::last_os_error()
    );
}

fn nothing() -> SeccompPolicy {
    SeccompPolicy::derive(&PermissionLattice::permissive(), NetworkEgress::Declared)
}

#[test]
fn the_launcher_binds_the_workspace_read_only_for_the_child_and_not_for_the_host() {
    use std::os::unix::fs::PermissionsExt;
    let admission = ChildConfinement::workload(
        ContainmentMode::MicroVM,
        Some(65534),
        UnsandboxedOptIn::Absent,
        LandlockWaiver::Absent,
    );
    if nucleus::runtime_uid() != 0 {
        assert!(admission.is_err());
        return;
    }
    let confinement = admission.expect("root Linux must enforce Landlock and drop the UID");
    let pid = std::process::id();

    // The image side: an empty directory on a read-only filesystem under /data/work.
    let image = PathBuf::from(format!("/data/work/nucleus-bind-test-{pid}"));
    std::fs::create_dir_all(&image).unwrap();
    mount("tmpfs", &image, "tmpfs", 0);
    let target = image.join("checkout");
    std::fs::create_dir(&target).unwrap();
    std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
    mount("none", &image, "", libc::MS_REMOUNT | libc::MS_RDONLY);

    // The work side: a work dir whose `src` holds the bytes to show, and a
    // world-executable copy of this binary for uid 65534 to run.
    let base = std::env::temp_dir().join(format!("nucleus-workspace-bind-{pid}"));
    let _cleanup = Cleanup(vec![base.clone(), image.clone()], vec![image.clone()]);
    let work = base.join("work");
    std::fs::create_dir_all(work.join("src")).unwrap();
    for d in [&base, &work, &work.join("src")] {
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    std::fs::write(work.join("src/marker"), b"from-the-work-dir").unwrap();
    std::fs::set_permissions(
        work.join("src/marker"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let child = base.join("child");
    std::fs::copy(std::env::current_exe().unwrap(), &child).unwrap();
    std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o755)).unwrap();

    let bind = WorkspaceBind::compile(&work, "src", target.to_str().unwrap())
        .expect("an empty read-only image directory under /data/work is a bind target");

    let mut cmd = Command::new(&child);
    cmd.args([
        "--exact",
        "child_entry",
        "--nocapture",
        "--test-threads=1",
        "-q",
    ])
    .env(TARGET_ENV, &target)
    .current_dir(Path::new("/"));
    let hardening = confinement.apply_with_namespaces(
        &mut cmd,
        nucleus::RlimitPolicy::node_ceiling().at_ceiling(),
        nothing(),
        &nucleus::WorkspaceWrites::Writable,
        NamespaceRequest {
            pids: PidNamespace::Own,
            network: NetworkNamespace::Shared,
            user_namespace_uid: None,
            workspace_bind: Some(bind),
        },
    );
    let nucleus::SpawnHardening::Hardened(h) = hardening else {
        panic!("the bind was not installed: {hardening:?}");
    };
    assert_eq!(h.workspace_bind(), Some(bind), "the receipt names the bind");

    let out = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let result = stdout
        .lines()
        .find_map(|l| l.strip_prefix(RESULT))
        .unwrap_or_else(|| {
            panic!(
                "no result line (status {}); stdout:\n{stdout}\nstderr:\n{}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            )
        })
        .to_owned();
    // The child reads the work dir's bytes at the image path, as uid 65534,
    // and cannot write through it.
    assert!(result.contains("marker=from-the-work-dir "), "{result}");
    assert!(
        result.contains(&format!("write=errno={} ", libc::EROFS)),
        "{result}"
    );
    assert!(result.ends_with("uid=65534"), "{result}");
    let options = result
        .split(' ')
        .find_map(|f| f.strip_prefix("options="))
        .unwrap();
    for flag in ["ro", "nosuid", "nodev", "noexec"] {
        assert!(
            options.split(',').any(|o| o == flag),
            "{flag} missing: {result}"
        );
    }

    // The host's namespace never saw it: the directory is still empty, and
    // no mount sits on it.
    assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0);
    let host = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
    assert!(
        !host
            .lines()
            .any(|l| l.split(' ').nth(4) == Some(target.to_str().unwrap())),
        "the bind leaked into the runtime's mount namespace"
    );
    assert!(!work.join("src/new").exists());
}

/// A bind needs the workload's own mount namespace: without a PID namespace
/// of its own there is none, and the spawn is refused, not run unbound.
#[test]
fn a_bind_without_the_workloads_own_namespace_is_refused() {
    let Ok(confinement) = ChildConfinement::workload(
        ContainmentMode::MicroVM,
        Some(65534),
        UnsandboxedOptIn::Absent,
        LandlockWaiver::Absent,
    ) else {
        return;
    };
    let pid = std::process::id();
    let base = std::env::temp_dir().join(format!("nucleus-workspace-bind-shared-{pid}"));
    let image = PathBuf::from(format!("/data/work/nucleus-bind-shared-{pid}"));
    let _cleanup = Cleanup(vec![base.clone(), image.clone()], vec![image.clone()]);
    std::fs::create_dir_all(base.join("work/src")).unwrap();
    std::fs::create_dir_all(&image).unwrap();
    mount("tmpfs", &image, "tmpfs", 0);
    std::fs::create_dir(image.join("checkout")).unwrap();
    mount("none", &image, "", libc::MS_REMOUNT | libc::MS_RDONLY);
    let bind = WorkspaceBind::compile(
        &base.join("work"),
        "src",
        image.join("checkout").to_str().unwrap(),
    )
    .unwrap();
    let mut cmd = Command::new("/bin/true");
    let hardening = confinement.apply_with_namespaces(
        &mut cmd,
        nucleus::RlimitPolicy::node_ceiling().at_ceiling(),
        nothing(),
        &nucleus::WorkspaceWrites::Writable,
        NamespaceRequest {
            pids: PidNamespace::Shared,
            network: NetworkNamespace::Shared,
            user_namespace_uid: None,
            workspace_bind: Some(bind),
        },
    );
    assert_eq!(
        hardening,
        nucleus::SpawnHardening::Unhardened(nucleus::Unhardened::Refused)
    );
    assert!(cmd.status().is_err(), "a refused spawn must not run");
}
