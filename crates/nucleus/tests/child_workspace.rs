//! A read-only workspace, observed on a REAL child (#2907).
//!
//! A pod whose lattice says `write_files: never` and `edit_files: never`
//! holds every child's workspace read-only with the Landlock write layer.
//! Before this, the proxy refused the agent's own write tool while a
//! `run_bash` child (and the workload) wrote the workspace freely, in every
//! driver.
//!
//! Each test spawns this test binary again as the child, confined by
//! `ChildConfinement::apply` exactly as the tool-proxy's workload and the
//! Executor's `/v1/run` children are. The child runs one filesystem
//! operation, selected by an environment variable, and prints the result.
//! Every denial is paired with a CONTROL: the same operation, by a child in
//! the same posture with a writable workspace. A denial counts only where the
//! control succeeded, so DAC cannot pass for Landlock.
//!
//! These run unprivileged, under the postures a non-root runtime has (the
//! bare tier a local driver runs, and `HostHardened`). Run as root they use
//! the postures a root runtime has instead (the root container's uid drop,
//! and a root `HostHardened`'s). On a kernel without Landlock they check the other half
//! of the rule: the read-only workspace is refused by name, and no child
//! starts.

#![cfg(target_os = "linux")]

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use nucleus::portcullis::{NetworkEgress, PermissionLattice, SeccompPolicy};
use nucleus::{
    ChildConfinement, ContainmentMode, LandlockSupport, LandlockWaiver, NucleusError,
    UnsandboxedOptIn, WorkspaceWrites,
};

const OP_ENV: &str = "NUCLEUS_CHILD_WORKSPACE_OP";
const RESULT: &str = "CHILD_WORKSPACE_RESULT ";

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
        // A new file.
        "create" => rendered(std::fs::write(arg, b"new")),
        // An existing file, opened for writing without O_CREAT or O_TRUNC.
        "modify" => rendered(
            std::fs::OpenOptions::new()
                .write(true)
                .open(arg)
                .and_then(|mut f| f.write_all(b"changed")),
        ),
        "truncate" => rendered(
            std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(arg),
        ),
        "mkdir" => rendered(std::fs::create_dir(arg)),
        "unlink" => rendered(std::fs::remove_file(arg)),
        "read" => rendered(std::fs::read(arg)),
        "list" => rendered(std::fs::read_dir(arg)),
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

/// A world-writable directory under `parent`, removed on drop.
fn scratch(parent: &Path, tag: &str) -> Scratch {
    let dir = parent.join(format!(
        "nucleus-workspace-{tag}-{}-{}",
        std::process::id(),
        std::thread::current()
            .name()
            .unwrap_or("t")
            .replace("::", "-")
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    Scratch(dir)
}

/// Where the test's workspace lives: outside the write layer's scratch, or
/// the layer refuses it for overlapping (`/tmp`, where `tempfile` would put
/// it). Cargo's per-target scratch is writable wherever the build is (a gate
/// sandbox that writes only `target/` included); if the target dir is itself
/// under `/tmp`, `/var/tmp`, which is not scratch.
fn workspace_parent() -> PathBuf {
    // A root run's children drop to an unprivileged uid, which may not be
    // able to traverse a home directory holding `target/`; root can always
    // write `/var/tmp`, which every dropped uid can reach.
    if nucleus::runtime_uid() == 0 {
        return PathBuf::from("/var/tmp");
    }
    let target_tmp = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    std::fs::create_dir_all(&target_tmp).unwrap();
    let resolved = std::fs::canonicalize(&target_tmp).unwrap();
    if resolved.starts_with("/tmp") {
        PathBuf::from("/var/tmp")
    } else {
        resolved
    }
}

/// A workspace seeded the way a pod's is: a source file the agent was given,
/// and the HOME the runtime makes.
struct Workspace {
    dir: Scratch,
}

impl Workspace {
    fn new(tag: &str) -> Self {
        let dir = scratch(&workspace_parent(), tag);
        let source = dir.0.join("main.rs");
        std::fs::write(&source, b"fn main() {}").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o666)).unwrap();
        let home = dir.0.join(nucleus_spec::guest_layout::WORKLOAD_HOME_NAME);
        std::fs::create_dir_all(&home).unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o777)).unwrap();
        Self { dir }
    }

    fn path(&self) -> &Path {
        &self.dir.0
    }

    fn source(&self) -> PathBuf {
        self.dir.0.join("main.rs")
    }

    fn home(&self) -> PathBuf {
        self.dir
            .0
            .join(nucleus_spec::guest_layout::WORKLOAD_HOME_NAME)
    }

    fn read_only(&self) -> WorkspaceWrites {
        WorkspaceWrites::ReadOnly {
            workspace: self.path().to_path_buf(),
        }
    }
}

/// The child binary: this one, or, for a root runtime whose children drop
/// their uid, a copy where the dropped uid can execute it.
fn child_exe(dir: &Scratch) -> PathBuf {
    let me = std::env::current_exe().expect("current_exe");
    if nucleus::runtime_uid() != 0 {
        return me;
    }
    let path = dir.0.join("child");
    std::fs::copy(&me, &path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// The postures this runtime gives a pod's children: a root runtime's (the
/// root container's uid drop, a root `HostHardened`'s) or a non-root one's (the bare
/// tier a local driver runs, `HostHardened`).
fn postures() -> Vec<(&'static str, ChildConfinement)> {
    let waiver = LandlockWaiver::Absent;
    let mut out = Vec::new();
    if nucleus::runtime_uid() == 0 {
        out.push((
            "root Unsandboxed (root container image)",
            ChildConfinement::for_containment(
                ContainmentMode::Unsandboxed,
                UnsandboxedOptIn::Absent,
                waiver,
            )
            .unwrap(),
        ));
        // Not `MicroVM`: its guest-layout layer makes this host's `/var/tmp`
        // read-only, so the writable control could not write. The write layer
        // does not depend on the posture it is installed in.
        out.push((
            "root HostHardened",
            ChildConfinement::for_containment(
                ContainmentMode::HostHardened,
                UnsandboxedOptIn::Absent,
                waiver,
            )
            .unwrap(),
        ));
    } else {
        out.push((
            "bare tier (local driver)",
            ChildConfinement::for_containment(
                ContainmentMode::Unsandboxed,
                UnsandboxedOptIn::Explicit,
                waiver,
            )
            .unwrap(),
        ));
        out.push((
            "HostHardened",
            ChildConfinement::for_containment(
                ContainmentMode::HostHardened,
                UnsandboxedOptIn::Absent,
                waiver,
            )
            .unwrap(),
        ));
    }
    out
}

/// Run `op` in a child confined by `confinement` under `writes`; return its
/// result line, or the spawn's failure.
fn try_run(
    exe: &Path,
    confinement: ChildConfinement,
    writes: &WorkspaceWrites,
    op: &str,
) -> std::io::Result<String> {
    confinement
        .preflight_filesystem(writes)
        .map_err(std::io::Error::other)?;
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
    let nothing = SeccompPolicy::derive(&PermissionLattice::permissive(), NetworkEgress::Declared);
    let _ = confinement.apply(
        &mut cmd,
        nucleus::RlimitPolicy::node_ceiling().at_ceiling(),
        nothing,
        writes,
    );
    let out = cmd.output()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    Ok(stdout
        .lines()
        .find_map(|l| l.strip_prefix(RESULT))
        .map(str::to_string)
        .unwrap_or_else(|| {
            panic!(
                "{op}: no result line (status {}); stdout:\n{stdout}\nstderr:\n{}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            )
        }))
}

fn run(exe: &Path, confinement: ChildConfinement, writes: &WorkspaceWrites, op: &str) -> String {
    try_run(exe, confinement, writes, op)
        .unwrap_or_else(|e| panic!("{op}: the confined child did not spawn: {e}"))
}

fn denied() -> String {
    format!("errno={}", libc::EACCES)
}

/// On a kernel without Landlock the rule's other half is what holds: a
/// read-only workspace is refused by name in every posture, and no child
/// starts. Returns whether the kernel enforces, so a test that needs the
/// layer stops here having checked something real.
fn landlock_or_refusal(ws: &Workspace) -> bool {
    let kernel = LandlockSupport::probe();
    if kernel.enforceable().is_some() {
        return true;
    }
    for (name, c) in postures() {
        match c.preflight_filesystem(&ws.read_only()) {
            Err(NucleusError::WorkspaceReadOnlyUnenforceable { workspace, .. }) => {
                assert_eq!(Path::new(&workspace), ws.path(), "{name}");
            }
            other => panic!("{name}: {kernel} must refuse a read-only workspace: {other:?}"),
        }
    }
    eprintln!("this kernel offers {kernel}: checked the refusal by name, not the layer");
    false
}

/// THE property (#2907): a child of a `write_files: never` pod cannot
/// create, modify, truncate, remove or make a directory in its workspace,
/// in every posture this runtime has, the bare tier included. The control,
/// the same posture with a writable workspace, does each one. Red on main,
/// where a read-only workspace had no write layer: every confined operation
/// succeeds like the control.
#[test]
fn a_child_of_a_read_only_workspace_cannot_write_it() {
    let bin = scratch(&std::env::temp_dir(), "bin");
    let exe = child_exe(&bin);
    let ws = Workspace::new("ro");
    if !landlock_or_refusal(&ws) {
        return;
    }
    for (name, c) in postures() {
        let fresh = ws.path().join(format!("created-{}", name.len()));
        let dir = ws.path().join(format!("dir-{}", name.len()));
        let ro = ws.read_only();
        // Denied, each against a control that does it.
        for (op, undo) in [
            (format!("create:{}", fresh.display()), Some(fresh.clone())),
            (format!("mkdir:{}", dir.display()), Some(dir.clone())),
            (format!("modify:{}", ws.source().display()), None),
            (format!("truncate:{}", ws.source().display()), None),
        ] {
            assert_eq!(run(&exe, c, &ro, &op), denied(), "{name}: {op}");
            assert_eq!(
                run(&exe, c, &WorkspaceWrites::Writable, &op),
                "ok",
                "{name}: control {op}"
            );
            if let Some(path) = undo {
                let _ = std::fs::remove_file(&path);
                let _ = std::fs::remove_dir(&path);
            }
            std::fs::write(ws.source(), b"fn main() {}").unwrap();
        }
        let unlink = format!("unlink:{}", ws.source().display());
        assert_eq!(run(&exe, c, &ro, &unlink), denied(), "{name}");
        assert!(ws.source().exists(), "{name}: the source survived");
        assert_eq!(
            std::fs::read(ws.source()).unwrap(),
            b"fn main() {}",
            "{name}: the source is unchanged"
        );
        // Still readable: the layer takes writes away and nothing else.
        assert_eq!(
            run(&exe, c, &ro, &format!("read:{}", ws.source().display())),
            "ok",
            "{name}"
        );
        assert_eq!(
            run(&exe, c, &ro, &format!("list:{}", ws.path().display())),
            "ok",
            "{name}"
        );
    }
}

/// What the child still needs works under the layer: `/tmp`, `/dev/null`,
/// and the HOME the runtime made in the workspace. Red if the layer takes
/// the scratch away (every toolchain would fail as if broken), or if it is
/// not applied (then the denial above would not hold either).
#[test]
fn a_child_of_a_read_only_workspace_still_writes_the_runtime_scratch() {
    let bin = scratch(&std::env::temp_dir(), "bin");
    let exe = child_exe(&bin);
    let ws = Workspace::new("scratch");
    if !landlock_or_refusal(&ws) {
        return;
    }
    let tmp = scratch(Path::new("/tmp"), "tmp");
    for (name, c) in postures() {
        let ro = ws.read_only();
        let in_tmp = tmp.0.join(format!("t-{}", name.len()));
        assert_eq!(
            run(&exe, c, &ro, &format!("create:{}", in_tmp.display())),
            "ok",
            "{name}"
        );
        assert_eq!(run(&exe, c, &ro, "modify:/dev/null"), "ok", "{name}");
        let in_home = ws.home().join(format!("h-{}", name.len()));
        assert_eq!(
            run(&exe, c, &ro, &format!("create:{}", in_home.display())),
            "ok",
            "{name}"
        );
    }
}

/// The shipped `test-runner` profile (#2907) says `write_files: never` and
/// runs `cargo test`. Its children are held read-only: a build output in
/// the workspace (`target/`) is refused, and the same output under the
/// scratch (`CARGO_TARGET_DIR=/tmp/...`) is written. The rule is read off
/// the profile itself, so a profile that stopped saying `never` would red.
#[test]
fn the_test_runner_profile_builds_in_the_scratch_not_the_workspace() {
    let bin = scratch(&std::env::temp_dir(), "bin");
    let exe = child_exe(&bin);
    let ws = Workspace::new("runner");
    let lattice = nucleus::portcullis::profile::ProfileRegistry::canonical()
        .unwrap()
        .resolve("test-runner")
        .unwrap()
        .normalize();
    let writes = WorkspaceWrites::of(&lattice, ws.path());
    assert_eq!(writes, ws.read_only(), "test-runner is read-only");
    if !landlock_or_refusal(&ws) {
        return;
    }
    let tmp = scratch(Path::new("/tmp"), "target");
    for (name, c) in postures() {
        let in_ws = ws.path().join("target");
        assert_eq!(
            run(&exe, c, &writes, &format!("mkdir:{}", in_ws.display())),
            denied(),
            "{name}"
        );
        assert!(!in_ws.exists(), "{name}");
        let in_tmp = tmp.0.join(format!("target-{}", name.len()));
        assert_eq!(
            run(&exe, c, &writes, &format!("mkdir:{}", in_tmp.display())),
            "ok",
            "{name}"
        );
    }
}

/// A workspace the scratch covers cannot be held read-only, so its child is
/// refused by name before it spawns, never run with the workspace writable.
#[test]
fn a_workspace_under_the_scratch_is_refused_by_name() {
    let ws = scratch(Path::new("/tmp"), "under");
    let writes = WorkspaceWrites::ReadOnly {
        workspace: ws.0.clone(),
    };
    for (name, c) in postures() {
        match c.preflight_filesystem(&writes) {
            Err(NucleusError::LandlockRuleset { path, error }) => {
                assert!(error.contains("overlaps"), "{name}: {error}");
                assert!(
                    Path::new(&path).ends_with(ws.0.file_name().unwrap()),
                    "{name}"
                );
            }
            // No Landlock: refused for that, also by name.
            Err(NucleusError::WorkspaceReadOnlyUnenforceable { .. })
                if LandlockSupport::probe().enforceable().is_none() => {}
            other => panic!("{name}: {other:?}"),
        }
    }
}
