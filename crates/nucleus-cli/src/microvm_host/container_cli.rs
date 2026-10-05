//! The only file that runs the `container` CLI.
//!
//! # Every call has a deadline
//!
//! The spike watched the shared `container` service stall every operation for
//! about 40 minutes behind another session's wedged nested VM, and watched a
//! wedged `container exec` ignore `SIGTERM`. So nothing here waits without
//! bound: each call names a [`Deadline`], and on expiry the child gets
//! `SIGKILL` (what `Child::kill` sends on Unix), is reaped, and the caller gets
//! [`Outcome::TimedOut`] instead of a hang.
//!
//! # Outcomes are typed
//!
//! "Could not run it", "ran and failed" and "ran out of time" lead to different
//! decisions (a missing CLI is a preflight refusal, a timeout is an
//! unresponsive service), so they are different variants rather than one
//! error string (ADR 0007 A-1).

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use nucleus_spec::microvm_host::OWNER_LABEL;

use super::lifecycle::Owned;

/// The program every call runs, unless a test points elsewhere.
const PROGRAM: &str = "container";

/// The builder's size for `container build`. Every build passes it: a build
/// without `--cpus`/`--memory` recreates the builder at the runtime default
/// (2 CPUs, 2 GiB, observed), and the kernel needs more.
const BUILDER_CPUS: &str = "8";
const BUILDER_MEMORY: &str = "12g";

/// How long a call may take before it is killed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deadline {
    /// Reads that touch only local state: `--version`, `system status`, `list`.
    Query,
    /// Creating, starting or stopping a container.
    Lifecycle,
    /// A short command run inside a container.
    Exec,
    /// `container build` of the image or the kernel.
    Build,
    /// Copy a selected workspace or build its filesystem image.
    Workspace,
}

impl Deadline {
    /// The duration. `start` is inside `Lifecycle` on purpose: the supervisor
    /// must not wait on a wedged service for longer than this.
    pub const fn duration(self) -> Duration {
        match self {
            Self::Query => Duration::from_secs(15),
            Self::Lifecycle => Duration::from_secs(90),
            Self::Exec => Duration::from_secs(30),
            Self::Build => Duration::from_secs(60 * 60),
            Self::Workspace => Duration::from_secs(10 * 60),
        }
    }
}

/// What a call did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Exit status 0.
    Succeeded { stdout: String, stderr: String },
    /// Ran and exited non-zero, or was killed by a signal (`code: None`).
    Failed {
        code: Option<i32>,
        stdout: String,
        stderr: String,
    },
    /// Still running at the deadline, so it was killed and reaped.
    TimedOut { after: Duration },
    /// The program is not installed.
    Missing,
    /// The program exists and could not be started.
    SpawnFailed(String),
}

impl Outcome {
    /// Stdout of a successful call, or `None`.
    pub fn stdout(&self) -> Option<&str> {
        match self {
            Self::Succeeded { stdout, .. } => Some(stdout),
            _ => None,
        }
    }

    /// Whether the call exited 0.
    pub fn succeeded(&self) -> bool {
        matches!(self, Self::Succeeded { .. })
    }

    /// One line for an error message.
    pub fn describe(&self) -> String {
        match self {
            Self::Succeeded { .. } => "succeeded".into(),
            Self::Failed {
                code,
                stdout,
                stderr,
            } => {
                let text = if stderr.trim().is_empty() {
                    stdout
                } else {
                    stderr
                };
                let code = code.map_or_else(|| "a signal".to_string(), |c| format!("exit {c}"));
                format!("failed ({code}): {}", text.trim())
            }
            Self::TimedOut { after } => format!("timed out after {after:?} and was killed"),
            Self::Missing => "is not installed".into(),
            Self::SpawnFailed(e) => format!("could not be started: {e}"),
        }
    }
}

/// Run `program args` with a deadline, capturing its output.
///
/// Also used for the few non-`container` host facts preflight reads (`sysctl`,
/// `sw_vers`), so there is one implementation of "run with a deadline".
pub fn run_with_deadline<S: AsRef<str>>(program: &Path, args: &[S], deadline: Duration) -> Outcome {
    let mut child = match Command::new(program)
        .args(args.iter().map(AsRef::as_ref))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Outcome::Missing,
        Err(e) => return Outcome::SpawnFailed(e.to_string()),
    };
    // Drain both pipes on their own threads: a child that fills a pipe nobody
    // reads blocks forever, and would then always look like a timeout.
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if started.elapsed() >= deadline => break None,
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Outcome::SpawnFailed(format!("waiting: {e}"));
            }
        }
    };
    let Some(status) = status else {
        // SIGKILL, not SIGTERM: a wedged `container exec` ignores SIGTERM.
        let _ = child.kill();
        let _ = child.wait();
        return Outcome::TimedOut {
            after: started.elapsed(),
        };
    };
    // A grandchild can hold a pipe open after the child exits; do not wait on
    // it past a short grace.
    let grace = Duration::from_secs(2);
    let stdout = stdout.recv_timeout(grace).unwrap_or_default();
    let stderr = stderr.recv_timeout(grace).unwrap_or_default();
    if status.success() {
        Outcome::Succeeded { stdout, stderr }
    } else {
        Outcome::Failed {
            code: status.code(),
            stdout,
            stderr,
        }
    }
}

fn drain<R: Read + Send + 'static>(pipe: Option<R>) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut p) = pipe {
            let _ = p.read_to_end(&mut buf);
        }
        let _ = tx.send(String::from_utf8_lossy(&buf).into_owned());
    });
    rx
}

/// Everything `container run` is told when the host container is created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSpec {
    pub name: String,
    pub image: String,
    pub kernel: PathBuf,
    pub caps: Vec<String>,
    pub cpus: u32,
    pub memory: String,
    /// `(volume or host path, container path)`.
    pub mounts: Vec<(String, String)>,
    /// `(host port, container port)`, each published on `127.0.0.1` only.
    pub publish: Vec<(u16, u16)>,
    pub env_file: PathBuf,
}

impl RunSpec {
    /// The argv after `container`. Pure, so the flags a host is created with
    /// are testable without creating one.
    pub fn argv(&self) -> Vec<String> {
        let mut a: Vec<String> = vec![
            "run".into(),
            "--detach".into(),
            // The image's run-node entrypoint prepares the cgroup as PID 1.
            // A runtime-injected init would make that preparation refuse.
            "--name".into(),
            self.name.clone(),
            "--label".into(),
            format!("{OWNER_LABEL}={}", self.name),
            "--virtualization".into(),
            "--kernel".into(),
            self.kernel.display().to_string(),
            "--cpus".into(),
            self.cpus.to_string(),
            "--memory".into(),
            self.memory.clone(),
            "--env-file".into(),
            self.env_file.display().to_string(),
        ];
        for cap in &self.caps {
            a.extend(["--cap-add".into(), cap.clone()]);
        }
        a.extend(["--read-only-path".into(), "NONE".into()]);
        for path in nucleus_spec::microvm_host::HOST_READONLY_PATHS {
            a.extend(["--read-only-path".into(), (*path).into()]);
        }
        for (src, dst) in &self.mounts {
            a.extend(["--volume".into(), format!("{src}:{dst}")]);
        }
        for (host, container) in &self.publish {
            a.extend(["--publish".into(), format!("127.0.0.1:{host}:{container}")]);
        }
        a.push(self.image.clone());
        a
    }
}

/// The `container` CLI.
#[derive(Debug, Clone)]
pub struct ContainerCli {
    program: PathBuf,
}

impl ContainerCli {
    /// The CLI on `PATH`.
    pub fn system() -> Self {
        Self {
            program: PathBuf::from(PROGRAM),
        }
    }

    /// A different program standing in for `container`, for tests.
    #[cfg(test)]
    pub fn at(program: PathBuf) -> Self {
        Self { program }
    }

    fn call<S: AsRef<str>>(&self, args: &[S], deadline: Deadline) -> Outcome {
        run_with_deadline(&self.program, args, deadline.duration())
    }

    /// `container --version`.
    pub fn version(&self) -> Outcome {
        self.call(&["--version"], Deadline::Query)
    }

    /// `container system status --format json`.
    pub fn system_status(&self) -> Outcome {
        self.call(&["system", "status", "--format", "json"], Deadline::Query)
    }

    /// `container list --all --format json`.
    pub fn list_all(&self) -> Outcome {
        self.call(&["list", "--all", "--format", "json"], Deadline::Query)
    }

    /// `container volume create <name>`; an existing volume is not an error
    /// the caller can act on, so the caller lists first.
    pub fn volume_create(&self, name: &str) -> Outcome {
        self.call(&["volume", "create", name], Deadline::Lifecycle)
    }

    /// `container volume list --format json`.
    pub fn volume_list(&self) -> Outcome {
        self.call(&["volume", "list", "--format", "json"], Deadline::Query)
    }

    /// `container run …`: create and start the host container.
    pub fn run(&self, spec: &RunSpec) -> Outcome {
        self.call(&spec.argv(), Deadline::Lifecycle)
    }

    /// `container start <name>`.
    pub fn start(&self, c: &Owned) -> Outcome {
        self.call(&["start", c.name()], Deadline::Lifecycle)
    }

    /// `container stop <name>`.
    pub fn stop(&self, c: &Owned) -> Outcome {
        self.call(&["stop", "--time", "5", c.name()], Deadline::Lifecycle)
    }

    /// `container kill <name>`: what a crash looks like, for the live test.
    pub fn kill(&self, c: &Owned) -> Outcome {
        self.call(&["kill", c.name()], Deadline::Lifecycle)
    }

    /// `container volume delete <name>`.
    pub fn volume_delete(&self, name: &str) -> Outcome {
        self.call(&["volume", "delete", name], Deadline::Lifecycle)
    }

    /// `container delete --force <name>`.
    pub fn delete(&self, c: &Owned) -> Outcome {
        self.call(&["delete", "--force", c.name()], Deadline::Lifecycle)
    }

    /// `container exec <name> <argv…>`, without `-i`: no stdin is carried,
    /// so the full-duplex stall cannot occur.
    pub fn exec(&self, c: &Owned, argv: &[&str]) -> Outcome {
        let mut a = vec!["exec", c.name()];
        a.extend_from_slice(argv);
        self.call(&a, Deadline::Exec)
    }

    /// Copy an absolute local path into a checked host. No shell interprets paths.
    pub fn copy_into(&self, c: &Owned, source: &str, destination: &str) -> Outcome {
        self.call(
            &["copy", source, &format!("{}:{destination}", c.name())],
            Deadline::Workspace,
        )
    }

    /// Filesystem construction can exceed the short observation deadline.
    pub fn exec_workspace(&self, c: &Owned, argv: &[&str]) -> Outcome {
        let mut a = vec!["exec", c.name()];
        a.extend_from_slice(argv);
        self.call(&a, Deadline::Workspace)
    }

    /// `container exec --detach <name> <argv…>`: start a process and return.
    pub fn exec_detached(&self, c: &Owned, argv: &[&str]) -> Outcome {
        let mut a = vec!["exec", "--detach", c.name()];
        a.extend_from_slice(argv);
        self.call(&a, Deadline::Exec)
    }

    /// `container logs <name>`.
    pub fn logs(&self, c: &Owned) -> Outcome {
        self.call(&["logs", c.name()], Deadline::Query)
    }

    /// `container build` of an image from `containerfile` in `context`.
    pub fn build_image(
        &self,
        containerfile: &Path,
        tag: &str,
        build_args: &[(&str, &str)],
        context: &Path,
    ) -> Outcome {
        let mut a: Vec<String> = vec![
            "build".into(),
            "--cpus".into(),
            BUILDER_CPUS.into(),
            "--memory".into(),
            BUILDER_MEMORY.into(),
            "--progress".into(),
            "plain".into(),
            "--file".into(),
            containerfile.display().to_string(),
            "--tag".into(),
            tag.into(),
        ];
        for (k, v) in build_args {
            a.extend(["--build-arg".into(), format!("{k}={v}")]);
        }
        a.push(context.display().to_string());
        self.call(&a, Deadline::Build)
    }

    /// `container build -o type=local`: build a recipe whose output is files.
    pub fn build_to_dir(&self, containerfile: &Path, out: &Path, context: &Path) -> Outcome {
        self.call(
            &[
                "build".to_string(),
                "--cpus".into(),
                BUILDER_CPUS.into(),
                "--memory".into(),
                BUILDER_MEMORY.into(),
                "--progress".into(),
                "plain".into(),
                "--file".into(),
                containerfile.display().to_string(),
                "--output".into(),
                format!("type=local,dest={}", out.display()),
                context.display().to_string(),
            ],
            Deadline::Build,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A program standing in for a wedged `container`: `sleep` with the
    /// arguments it is given. `sleep` ignores everything but a duration, and
    /// the argv here is only a duration.
    fn sleep() -> PathBuf {
        PathBuf::from("/bin/sleep")
    }

    #[test]
    fn a_call_past_its_deadline_is_killed_not_waited_for() {
        let started = Instant::now();
        let out = run_with_deadline(&sleep(), &["30"], Duration::from_millis(300));
        let took = started.elapsed();
        assert!(matches!(out, Outcome::TimedOut { .. }), "{out:?}");
        assert!(
            took < Duration::from_secs(5),
            "waited {took:?} for a 300 ms deadline"
        );
    }

    #[test]
    fn a_call_inside_its_deadline_reports_its_exit() {
        let ok = run_with_deadline(&sleep(), &["0"], Duration::from_secs(10));
        assert!(ok.succeeded(), "{ok:?}");
        let failed = run_with_deadline(&sleep(), &["not-a-number"], Duration::from_secs(10));
        assert!(
            matches!(failed, Outcome::Failed { code: Some(c), .. } if c != 0),
            "{failed:?}"
        );
    }

    #[test]
    fn a_missing_program_is_missing_not_failed() {
        let out = ContainerCli::at(PathBuf::from("/nonexistent/container")).version();
        assert_eq!(out, Outcome::Missing);
    }

    #[test]
    fn stdout_is_captured() {
        let out = run_with_deadline(Path::new("/bin/echo"), &["hello"], Duration::from_secs(10));
        assert_eq!(out.stdout().map(str::trim), Some("hello"));
    }

    #[test]
    fn the_run_argv_carries_every_measured_requirement() {
        let spec = RunSpec {
            name: "nucleus-dev-microvm-host".into(),
            image: "nucleus-dev-microvm-host:local".into(),
            kernel: PathBuf::from("/k/Image"),
            caps: vec!["CAP_NET_ADMIN".into(), "CAP_SYS_ADMIN".into()],
            cpus: 4,
            memory: "4g".into(),
            mounts: vec![("vol".into(), "/srv".into())],
            publish: vec![(40001, 8080)],
            env_file: PathBuf::from("/s/node.env"),
        };
        assert!(!spec.argv().iter().any(|arg| arg == "--init"));
        let argv = spec.argv().join(" ");
        for want in [
            "--virtualization",
            "--kernel /k/Image",
            "--cap-add CAP_NET_ADMIN",
            "--cap-add CAP_SYS_ADMIN",
            "--volume vol:/srv",
            "--publish 127.0.0.1:40001:8080",
            "--label org.nucleus.microvm-host=nucleus-dev-microvm-host",
            "--env-file /s/node.env",
            "--read-only-path NONE",
        ] {
            assert!(argv.contains(want), "{want} missing from {argv}");
        }
        assert!(argv.ends_with("nucleus-dev-microvm-host:local"));
        for path in nucleus_spec::microvm_host::HOST_READONLY_PATHS {
            assert!(argv.contains(&format!("--read-only-path {path}")));
        }
        assert!(
            !argv.contains("0.0.0.0"),
            "a port was published beyond loopback"
        );
    }

    /// Nothing else in the crate runs `container`.
    #[test]
    fn this_is_the_only_file_that_runs_container() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders = Vec::new();
        let mut stack = vec![src];
        let mut seen = 0;
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("read src") {
                let path = entry.expect("entry").path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    seen += 1;
                    let text = std::fs::read_to_string(&path).expect("read");
                    if !path.ends_with("container_cli.rs")
                        && text.contains("\"container\"")
                        && text.contains("Command::new")
                    {
                        offenders.push(path);
                    }
                }
            }
        }
        assert!(seen > 10, "the scan found {seen} files; it is not looking");
        assert!(
            offenders.is_empty(),
            "these run `container` directly: {offenders:?}"
        );
    }
}
