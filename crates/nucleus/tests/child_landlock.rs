//! The workload's Landlock ruleset, observed on a REAL confined child
//! (#2696 P3c).
//!
//! Each test spawns this test binary again as the child, confined by
//! `ChildConfinement::apply` exactly as the tool-proxy's workload and the
//! Executor's `/v1/run` children are. The child runs one filesystem
//! operation, selected by an environment variable, and prints the result.
//! Every denial is paired with a CONTROL: the same operation, by a child at
//! the same uid with the same syscall filter, and no Landlock. A denial
//! counts only where the control succeeded, so DAC cannot pass for Landlock.
//!
//! These need root (only a root runtime confines a `MicroVM` child) and a
//! kernel with Landlock ABI 2 or newer, so they are `#[ignore]`d and run
//! explicitly:
//!
//! ```text
//! cargo test -p nucleus --test child_landlock --no-run
//! sudo <the built binary> --ignored --test-threads=1
//! ```
//!
//! Run that way they REFUSE to pass on the wrong host (not root, or no
//! Landlock): a run that confined nothing is not a pass.
//!
//! The paths are ones every Linux host has, chosen against the guest
//! layout's table: `/tmp` is writable there, `/var/tmp` is not (it is image
//! space, read-only for the workload), and `/run` is hidden.

#![cfg(target_os = "linux")]

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use nucleus::{
    ChildConfinement, ContainmentMode, FilesystemConfinement, LandlockSupport, LandlockWaiver,
    UnsandboxedOptIn,
};

const OP_ENV: &str = "NUCLEUS_CHILD_LANDLOCK_OP";
const RESULT: &str = "CHILD_LANDLOCK_RESULT ";

// ---------------------------------------------------------------- child side

/// The child's entry point. A no-op when run as an ordinary test.
#[test]
fn child_entry() {
    let Ok(op) = std::env::var(OP_ENV) else {
        return;
    };
    let result = run_op(&op);
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{RESULT}{result}");
    let _ = out.flush();
    std::process::exit(0);
}

fn rendered<T>(r: std::io::Result<T>) -> String {
    match r {
        Ok(_) => "ok".to_string(),
        Err(e) => format!("errno={}", e.raw_os_error().unwrap_or(-1)),
    }
}

fn run_op(op: &str) -> String {
    let (verb, arg) = op.split_once(':').unwrap_or((op, ""));
    match verb {
        "write" => rendered(std::fs::write(arg, b"x")),
        "read" => rendered(std::fs::read(arg)),
        "list" => rendered(std::fs::read_dir(arg)),
        "connect" => rendered(std::os::unix::net::UnixStream::connect(arg)),
        "exec" => match Command::new(arg).status() {
            Ok(s) if s.success() => "ok".to_string(),
            Ok(s) => format!("status={s}"),
            Err(e) => format!("errno={}", e.raw_os_error().unwrap_or(-1)),
        },
        other => format!("unknown-op={other}"),
    }
}

// --------------------------------------------------------------- parent side

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A world-traversable directory owned by root, removed on drop.
fn scratch(parent: &str, tag: &str) -> Scratch {
    let dir = Path::new(parent).join(format!("nucleus-landlock-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    Scratch(dir)
}

/// The child binary, copied where a dropped uid can execute it. `/tmp` is
/// writable, and so executable, under the guest ruleset.
fn child_exe(dir: &Scratch) -> PathBuf {
    let me = std::env::current_exe().expect("current_exe");
    let path = dir.0.join("child");
    std::fs::copy(&me, &path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// Run `op` in a child confined by `confinement`; return its result line.
fn run(exe: &Path, confinement: ChildConfinement, op: &str) -> String {
    let mut cmd = Command::new(exe);
    cmd.args([
        "--exact",
        "child_entry",
        "--nocapture",
        "--test-threads=1",
        "-q",
    ])
    .env(OP_ENV, op)
    .current_dir(Path::new("/"));
    // The derived policy that adds nothing: this file is about the ruleset.
    let nothing = nucleus::portcullis::SeccompPolicy::derive(
        &nucleus::portcullis::PermissionLattice::permissive(),
        nucleus::portcullis::NetworkEgress::Declared,
    );
    let _ = confinement.apply(
        &mut cmd,
        nucleus::RlimitPolicy::node_ceiling().at_ceiling(),
        nothing,
    );
    let out = cmd
        .output()
        .unwrap_or_else(|e| panic!("{op}: the confined child did not spawn: {e}"));
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .lines()
        .find_map(|l| l.strip_prefix(RESULT))
        .map(str::to_string)
        .unwrap_or_else(|| {
            panic!(
                "{op}: no result line (status {}); stdout:\n{stdout}\nstderr:\n{}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            )
        })
}

/// The confined child (MicroVM: uid drop, denylist, Landlock) and its control
/// (HostHardened on a root runtime: the same uid drop and denylist, no
/// Landlock). Refuses to run where the confined posture is not Landlock.
fn confined_and_control() -> (ChildConfinement, ChildConfinement) {
    assert_eq!(
        nucleus::runtime_uid(),
        0,
        "run as root: only a root runtime confines a MicroVM child"
    );
    let kernel = LandlockSupport::probe();
    assert!(
        kernel.enforceable().is_some(),
        "this host offers {kernel}; these tests need Landlock ABI {} or newer",
        nucleus::MIN_LANDLOCK_ABI
    );
    let confined = ChildConfinement::workload(
        ContainmentMode::MicroVM,
        None,
        UnsandboxedOptIn::Absent,
        LandlockWaiver::Absent,
    )
    .expect("a root runtime on a Landlock kernel confines");
    assert!(
        matches!(
            confined.filesystem(),
            FilesystemConfinement::Landlock { .. }
        ),
        "non-vacuity: {:?}",
        confined.filesystem()
    );
    let control = ChildConfinement::workload(
        ContainmentMode::HostHardened,
        None,
        UnsandboxedOptIn::Absent,
        LandlockWaiver::Absent,
    )
    .unwrap();
    assert_eq!(control.filesystem(), FilesystemConfinement::NotApplied);
    assert_eq!(
        control.drop_uid(),
        confined.drop_uid(),
        "same uid, or DAC decides"
    );
    (confined, control)
}

fn denied() -> String {
    format!("errno={}", libc::EACCES)
}

/// THE property (#2696 P3c): the workload writes where the layout says it may
/// and nowhere else. `/var/tmp` is world-writable, so the control writes it;
/// the confined child cannot. Red if the ruleset is not applied, or if it
/// grants image space write.
#[test]
#[ignore = "needs root and Landlock ABI >= 2; see the module docs"]
fn a_confined_child_cannot_write_outside_its_writable_dirs() {
    let (confined, control) = confined_and_control();
    let bin = scratch("/tmp", "bin");
    let exe = child_exe(&bin);
    let outside = scratch("/var/tmp", "w");
    std::fs::set_permissions(&outside.0, std::fs::Permissions::from_mode(0o1777)).unwrap();
    let target = outside.0.join("escape");
    let op = format!("write:{}", target.display());
    assert_eq!(
        run(&exe, control, &op),
        "ok",
        "control: DAC allows the write"
    );
    let _ = std::fs::remove_file(&target);
    assert_eq!(
        run(&exe, confined, &op),
        denied(),
        "Landlock must refuse it"
    );
    assert!(!target.exists());

    // Its own scratch stays writable: the denial is the ruleset, not a
    // broken child.
    let inside = scratch("/tmp", "ok");
    std::fs::set_permissions(&inside.0, std::fs::Permissions::from_mode(0o1777)).unwrap();
    let ok = inside.0.join("allowed");
    assert_eq!(
        run(&exe, confined, &format!("write:{}", ok.display())),
        "ok"
    );
}

/// Runtime state is hidden: a world-readable file under `/run` (where the
/// guest keeps the fetched spec and the SVID) is read by the control and
/// refused to the confined child, and its directory cannot be listed.
#[test]
#[ignore = "needs root and Landlock ABI >= 2; see the module docs"]
fn a_confined_child_cannot_read_a_hidden_path() {
    let (confined, control) = confined_and_control();
    let bin = scratch("/tmp", "bin");
    let exe = child_exe(&bin);
    let hidden = scratch("/run", "secret");
    let secret = hidden.0.join("spec.yaml");
    std::fs::write(&secret, b"secret").unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o644)).unwrap();
    let read = format!("read:{}", secret.display());
    let list = format!("list:{}", hidden.0.display());
    assert_eq!(
        run(&exe, control, &read),
        "ok",
        "control: DAC allows the read"
    );
    assert_eq!(run(&exe, control, &list), "ok");
    assert_eq!(run(&exe, confined, &read), denied());
    assert_eq!(run(&exe, confined, &list), denied());
}

/// What the workload needs still works under the ruleset: the workload door
/// (a socket under hidden `/run`; connecting is not a filesystem access
/// Landlock governs), `/dev/null`, the image's files, and exec from it.
#[test]
#[ignore = "needs root and Landlock ABI >= 2; see the module docs"]
fn the_door_devices_and_the_image_stay_usable_under_landlock() {
    let (confined, control) = confined_and_control();
    let bin = scratch("/tmp", "bin");
    let exe = child_exe(&bin);
    let door_dir = scratch("/run", "door");
    let door = door_dir.0.join("workload.sock");
    let listener = std::os::unix::net::UnixListener::bind(&door).unwrap();
    std::fs::set_permissions(&door, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(
        run(&exe, confined, &format!("connect:{}", door.display())),
        "ok"
    );
    drop(listener);
    assert_eq!(run(&exe, confined, "write:/dev/null"), "ok");
    // `/dev/stderr` is a link through `/proc` (read-only for the workload)
    // to the child's stderr pipe. Landlock must not change what reopening it
    // does. (Measured: the reopen is `EACCES` with or without Landlock, by
    // DAC, because the pipe belongs to the root parent; writing to the fd it
    // already holds, which is what `>&2` does, is unaffected.)
    assert_eq!(
        run(&exe, confined, "write:/dev/stderr"),
        run(&exe, control, "write:/dev/stderr")
    );
    assert_eq!(run(&exe, confined, "read:/etc/passwd"), "ok");
    assert_eq!(run(&exe, confined, "exec:/bin/true"), "ok");
}
