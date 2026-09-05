//! The raw synchronous spawn behind [`crate::ShellEffect::run_argv`] for
//! `RealEffects`, split out of `lib.rs` (line ratchet). Everything that gates
//! the spawn — the argv predicate and the authority spend — stays at the call
//! site in `lib.rs`; this is only the `Command` construction and execution.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;
use std::process::{Command, Output, Stdio};

pub(crate) fn spawn_sync(
    program: &str,
    args: &[String],
    cwd: &Path,
    stdin: Option<&[u8]>,
    allowed_env: &BTreeMap<String, String>,
    harden: Option<&(dyn Fn(&mut Command) + Send + Sync)>,
) -> io::Result<Output> {
    // Reproduces `Executor::spawn_checked` exactly so the raw spawn can
    // relocate here losslessly: env_clear + envs(allowlist), piped
    // stdout/stderr, stdin pipe-vs-null, host hardening via the injected
    // hook, and stdin-fed vs plain output.
    let mut cmd = Command::new(program);
    cmd.args(args)
        .current_dir(cwd)
        .env_clear() // Security: prevent secret leakage from parent
        .envs(allowed_env) // Only explicitly allowed vars
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Stdin: pipe it when the caller has data to write, otherwise close it.
    if stdin.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }

    // Host-hardening hook (e.g. `HostSandbox::harden_std`), applied just
    // before spawn. `None` reproduces the un-hardened spawn.
    if let Some(harden) = harden {
        harden(&mut cmd);
    }

    if let Some(input) = stdin {
        let mut child = cmd.spawn()?;
        if let Some(ref mut stdin_pipe) = child.stdin {
            use std::io::Write as _;
            stdin_pipe.write_all(input)?;
        }
        child.wait_with_output()
    } else {
        cmd.output()
    }
}
