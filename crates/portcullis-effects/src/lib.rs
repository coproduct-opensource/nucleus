//! Sealed effect traits — the primary surface for all I/O in nucleus.
//!
//! ## Design
//!
//! Effect types replace the capability lattice as the *primary* public surface.
//! Where previously callers interacted with `CapabilityLattice` fields at runtime,
//! they now receive a concrete effect handler whose only public constructor,
//! [`production_effects`], requires a policy. Bypassing policy is structurally
//! impossible: `RealEffects` is unconstructible outside this crate.
//!
//! ```text
//! Old surface:  caller builds CapabilityLattice, calls preflight, manually enforces
//! New surface:  caller receives impl FileEffect + WebEffect + …,
//!               policy is checked at every method call before I/O occurs
//! ```
//!
//! ## Usage
//!
//! ```rust,ignore
//! use portcullis_effects::{production_effects, FileEffect, WebEffect};
//! use portcullis_core::CapabilityLattice;
//!
//! let policy = CapabilityLattice {
//!     read_files: CapabilityLevel::Always,
//!     web_fetch: CapabilityLevel::LowRisk,
//!     ..CapabilityLattice::bottom()
//! };
//! let fx = production_effects(policy);
//!
//! // Policy is checked here, and the call consumes an `Authority` — the
//! // right to perform exactly this one action, earned from a preflight.
//! let contents = fx.read(Path::new("src/main.rs"), authority)?;
//! fx.fetch("https://example.com")?;
//! ```
//!
//! Most callers should not build authorities by hand: [`runtime::NucleusRuntime`]
//! pairs each `preflight_*` with the effect it authorizes.
//!
//! ```rust,ignore
//! let proof = rt.preflight_read()?;      // discharges the eight obligations
//! let data  = rt.read_file(&path, authority)?; // spends it on exactly this read
//! ```
//!
//! ## Testing
//!
//! ```rust
//! use portcullis_effects::{DenyAllEffects, RecordingEffects, FileEffect};
//! use portcullis_effects::authority::Authority;
//! use portcullis_core::discharge::test_helpers::bundle_for;
//! use portcullis_core::{Operation, SinkClass};
//!
//! let read_authority = || Authority::new(
//!     bundle_for(Operation::ReadFiles, SinkClass::AuditLogAppend));
//!
//! // DenyAllEffects rejects everything — useful for testing deny paths
//! let fx = DenyAllEffects;
//! assert!(fx.read(std::path::Path::new("file.txt"), read_authority()).is_err());
//!
//! // RecordingEffects records all calls — useful for asserting what was invoked
//! let fx = RecordingEffects::new();
//! let _ = fx.read(std::path::Path::new("file.txt"), read_authority());
//! assert_eq!(fx.calls().len(), 1);
//! ```

pub mod async_traits;
pub mod runtime;

pub mod authority;
pub mod receipt;

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};

use crate::authority::Authority;
use portcullis_core::discharge::DischargedBundle;
use portcullis_core::{CapabilityLattice, CapabilityLevel};

// ═══════════════════════════════════════════════════════════════════════════
// Error type
// ═══════════════════════════════════════════════════════════════════════════

/// Error returned by effect operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectError {
    /// The policy denied this operation. Contains the reason.
    PolicyDenied(String),
    /// The operation failed for an I/O reason.
    Io(String),
    /// The operation failed because a path is outside the allowed scope.
    PathViolation(String),
    /// A shell command failed.
    CommandFailed {
        exit_code: Option<i32>,
        stderr: String,
    },
    /// Feature not implemented in this effect handler.
    NotImplemented(&'static str),
}

impl std::fmt::Display for EffectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PolicyDenied(msg) => write!(f, "policy denied: {msg}"),
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
            Self::PathViolation(msg) => write!(f, "path violation: {msg}"),
            Self::CommandFailed { exit_code, stderr } => {
                write!(f, "command failed (exit={exit_code:?}): {stderr}")
            }
            Self::NotImplemented(feat) => write!(f, "not implemented: {feat}"),
        }
    }
}

impl std::error::Error for EffectError {}

// ═══════════════════════════════════════════════════════════════════════════
// Effect traits
// ═══════════════════════════════════════════════════════════════════════════

/// File system read/write operations.
///
/// # Mediation surface (B1/B2)
///
/// Every method takes an [`Authority`](crate::authority::Authority) **by value**.
/// That is the whole point and it buys two properties the previous surface did
/// not have:
///
/// * **Scoped** — the authority names the `(Operation, SinkClass)` it was earned
///   for, and spending it on a different pair fails. Previously these four
///   methods took no obligation token at all and were gated only by the coarse
///   capability lattice (`write_files != Never`), so none of the eight
///   obligations reached a file write.
/// * **One-shot** — by value means moved. Replaying an authority is a
///   move-after-move *compile* error, not a policy someone has to remember.
///
/// `read_str` is a provided method and consumes the authority it is handed,
/// forwarding it to `read` — one authority, one read.
///
/// # An authority pays for exactly one file effect
///
/// The second use below is a move-after-move **compile error**, not a runtime
/// check someone has to remember to write.
///
/// A `compile_fail` test passes when the snippet fails to compile FOR ANY
/// REASON, so dependence on the replay must be established rather than assumed:
/// deleting the second `write` makes this snippet COMPILE. That was checked by
/// perturbation, the same discipline the [`Authority`] doctest documents.
///
/// ```compile_fail,E0382
/// use portcullis_effects::{production_effects_concrete, FileEffect};
/// use portcullis_effects::authority::Authority;
/// use portcullis_core::discharge::test_helpers::bundle_for;
/// use portcullis_core::{CapabilityLattice, CapabilityLevel, Operation, SinkClass};
///
/// let fx = production_effects_concrete(CapabilityLattice {
///     write_files: CapabilityLevel::Always,
///     ..CapabilityLattice::bottom()
/// });
/// let authority = Authority::new(
///     bundle_for(Operation::WriteFiles, SinkClass::WorkspaceWrite));
///
/// let _first = fx.write(std::path::Path::new("/tmp/a"), b"x", authority);
/// // Replay: `authority` was moved by the first write.
/// let _second = fx.write(std::path::Path::new("/tmp/b"), b"x", authority);
/// ```
pub trait FileEffect {
    /// Read the full contents of a file.
    fn read(&self, path: &Path, authority: Authority) -> Result<Vec<u8>, EffectError>;

    /// Write bytes to a file, creating it if it does not exist.
    fn write(&self, path: &Path, content: &[u8], authority: Authority) -> Result<(), EffectError>;

    /// Append bytes to a file, creating it if it does not exist.
    fn append(&self, path: &Path, content: &[u8], authority: Authority) -> Result<(), EffectError>;

    /// List files matching a glob pattern. Returns absolute paths.
    fn glob(&self, pattern: &str, authority: Authority) -> Result<Vec<PathBuf>, EffectError>;

    /// Read the full contents of a file as UTF-8.
    fn read_str(&self, path: &Path, authority: Authority) -> Result<String, EffectError> {
        let bytes = self.read(path, authority)?;
        String::from_utf8(bytes).map_err(|e| EffectError::Io(format!("UTF-8 decode failed: {e}")))
    }
}

/// Web fetch and search operations.
///
/// Both methods consume an [`Authority`] by value — see [`FileEffect`] for what
/// that buys. Egress is an `HTTPEgress` sink, which `sink_min_integrity` holds to
/// `Untrusted`: a session that has observed adversarial content cannot discharge
/// for it at all, and before this change that check never reached a fetch.
pub trait WebEffect {
    /// Fetch the body of a URL. Returns raw bytes.
    fn fetch(&self, url: &str, authority: Authority) -> Result<Vec<u8>, EffectError>;

    /// Perform a web search and return result snippets.
    fn search(&self, query: &str, authority: Authority) -> Result<Vec<SearchResult>, EffectError>;
}

/// Shell command execution.
pub trait ShellEffect {
    /// Run a shell command and return stdout/stderr.
    ///
    /// `cmd` is parsed via `shell-words` to prevent injection.
    ///
    /// Consumes an [`Authority`] by value. `run_argv` already required a
    /// discharge; this method did not, so the unstructured path was the weaker
    /// of the two.
    fn run(&self, cmd: &str, authority: Authority) -> Result<ShellOutput, EffectError>;

    /// Structured argv spawn — the sealed home for a mediated process spawn (B1).
    ///
    /// Unlike [`run`](ShellEffect::run), this takes an already-split argv
    /// (`program` + `args`, never a shell string, preserving the
    /// "argv-not-shell" injection defense) plus everything a hardened spawn
    /// needs, so a caller such as the nucleus `Executor` can relocate its raw
    /// `Command::new` into this sealed home without losing any behavior:
    ///
    /// * `program` / `args` — the argv; no shell is ever involved.
    /// * `cwd` — the already-validated working directory (`current_dir`).
    /// * `stdin` — `Some(bytes)` to feed the child stdin over a pipe, `None` to
    ///   close it with `Stdio::null()`.
    /// * `allowed_env` — the environment allowlist; the child is spawned with
    ///   `env_clear()` then `envs(allowed_env)`, so no parent variable leaks.
    /// * `harden` — an optional hook applied to the built [`Command`] just
    ///   before spawn (e.g. the caller's host-sandbox `harden_std`). Injected as
    ///   a callback because the concrete hardening lives in the caller's crate,
    ///   not here; passing `None` reproduces the un-hardened spawn.
    ///
    /// Requires a `&DischargedBundle` — the sealed home only spawns past a
    /// discharged obligation bundle (minted by `preflight_action`). It is
    /// required by type but otherwise unused (`_proof`); its presence is the
    /// enforcement.
    #[allow(clippy::too_many_arguments)]
    fn run_argv(
        &self,
        program: &str,
        args: &[String],
        cwd: &Path,
        stdin: Option<&[u8]>,
        allowed_env: &BTreeMap<String, String>,
        harden: Option<&(dyn Fn(&mut Command) + Send + Sync)>,
        _authority: Authority,
    ) -> io::Result<Output>;
}

/// Async (tokio) structured argv spawn.
///
/// This lives in its own trait, **separate from [`ShellEffect`]**, so that
/// `ShellEffect` stays free of any `async fn` and therefore remains
/// dyn-compatible (`Arc<dyn ShellEffect>` must build a vtable — an `async fn`
/// in the trait would break that with `E0038`). Callers that need the async
/// spawn depend on this trait explicitly; the sync `Arc<dyn ShellEffect>`
/// consumers are unaffected.
///
/// The method mirrors [`ShellEffect::run_argv`] but on `tokio::process`, with
/// `kill_on_drop(true)` and an optional `timeout`. When `timeout` is `Some`,
/// the wait is wrapped in `tokio::time::timeout` and a timeout maps to an
/// [`io::ErrorKind::TimedOut`] error; when `None`, the child is awaited to
/// completion. Gated behind the `async` feature so the default crate stays free
/// of the tokio dependency.
///
/// (Distinct from [`async_traits::AsyncShellEffect`](crate::async_traits::AsyncShellEffect),
/// which is the sync→async *mirror* of `ShellEffect::run`; this trait is the
/// async home of the structured `run_argv` spawn.)
#[cfg(feature = "async")]
pub trait AsyncShellSpawnEffect {
    /// Async (tokio) variant of [`ShellEffect::run_argv`].
    #[allow(clippy::too_many_arguments, async_fn_in_trait)]
    async fn run_argv_async(
        &self,
        program: &str,
        args: &[String],
        cwd: &Path,
        stdin: Option<&[u8]>,
        allowed_env: &BTreeMap<String, String>,
        harden: Option<&(dyn Fn(&mut tokio::process::Command) + Send + Sync)>,
        timeout: Option<std::time::Duration>,
        _authority: Authority,
    ) -> io::Result<Output>;
}

/// Which net capability governs an egress, so the [`PolicyEnforced`] gate can
/// pick the matching policy field (`web_fetch` vs `web_search`) for a
/// [`NetEffect::fetch`] call — the net analogue of the single `run_bash` field
/// that gates the structured spawn.
#[cfg(feature = "net")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetCapability {
    /// Governed by `policy.web_fetch`.
    WebFetch,
    /// Governed by `policy.web_search`.
    WebSearch,
}

/// Sealed agent net-egress (the real reqwest HTTP send) — the net analogue of
/// [`AsyncShellSpawnEffect`] for process spawn (B5).
///
/// This is the sealed home for AGENT egress (`web_fetch` / `web_search`): the
/// only place a raw `reqwest …send()` may live on the effect path. The
/// tool-proxy handlers relocate their raw `state.web_client…send()` here and
/// reach it only past a minted [`DischargedBundle`], so an un-preflighted agent
/// egress is a type error exactly as an un-preflighted spawn is.
///
/// Like [`AsyncShellSpawnEffect`] this lives in its own trait (an `async fn`
/// would make [`WebEffect`] non-dyn-compatible) and is behind a cargo feature
/// (`net`) so the default crate and the async-spawn consumers do not pull the
/// reqwest HTTP stack.
///
/// The caller supplies the already-configured [`reqwest::Client`] (the
/// tool-proxy's shared `web_client`, built with its timeout/user-agent) plus the
/// request pieces the handlers already have — method, fully-formed URL (query
/// params folded in by the caller), header pairs, optional body, optional
/// per-request timeout. The full [`reqwest::Response`] is handed back so the
/// caller keeps doing its post-send security processing (redirect-target
/// recheck, MIME gating, header collection, capped body read) unchanged.
///
/// Requires a `&DischargedBundle` — the sealed home only sends past a discharged
/// obligation bundle (minted by `preflight_action`). It is required by type but
/// otherwise unused (`_proof`); its presence is the enforcement.
#[cfg(feature = "net")]
pub trait NetEffect {
    /// Perform the sealed agent HTTP egress and return the raw response.
    #[allow(clippy::too_many_arguments, async_fn_in_trait)]
    async fn fetch(
        &self,
        client: &reqwest::Client,
        cap: NetCapability,
        method: reqwest::Method,
        url: reqwest::Url,
        headers: &[(String, String)],
        body: Option<Vec<u8>>,
        timeout: Option<std::time::Duration>,
        _authority: Authority,
    ) -> Result<reqwest::Response, EffectError>;
}

/// Git operations.
///
/// Both methods consume an [`Authority`] by value. `push` is the
/// highest-consequence sink in the system and was gated only by
/// `git_push != Never` — the coarse capability — so a session too tainted to
/// discharge for `GitPush` could still push.
pub trait GitEffect {
    /// Create a git commit with the given message.
    fn commit(&self, message: &str, authority: Authority) -> Result<String, EffectError>;

    /// Push the current branch to a remote.
    fn push(&self, remote: &str, branch: &str, authority: Authority) -> Result<(), EffectError>;
}

/// Sub-agent spawn operations.
pub trait AgentSpawnEffect {
    /// Spawn a sub-agent at the given endpoint with the given term.
    ///
    /// Consumes an [`Authority`] by value. `AgentSpawn` is held to `Untrusted`
    /// minimum integrity because adversarial instructions would propagate to the
    /// child — a check that never reached this call before.
    fn spawn(
        &self,
        endpoint: &str,
        term_json: &str,
        authority: Authority,
    ) -> Result<String, EffectError>;
}

// ═══════════════════════════════════════════════════════════════════════════
// Supporting types
// ═══════════════════════════════════════════════════════════════════════════

/// Output from a shell command.
#[derive(Debug, Clone)]
pub struct ShellOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: i32,
}

impl ShellOutput {
    pub fn stdout_str(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
    pub fn stderr_str(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }
}

/// A single web search result.
#[derive(Debug, Clone)]
pub struct SearchResult {
    pub title: String,
    pub url: String,
    pub snippet: String,
}

// ═══════════════════════════════════════════════════════════════════════════
// Sealed real implementation
// ═══════════════════════════════════════════════════════════════════════════

/// Real I/O implementation. Unconstructible outside this crate.
///
/// The type is `pub` so a policy-enforced handle can be *named* by consumers
/// (e.g. nucleus's `Executor` holds `Arc<PolicyEnforced<RealEffects>>` to reach
/// the async spawn through a concrete type — `AsyncShellSpawnEffect` has an
/// `async fn` and is not dyn-compatible, so a trait object is impossible). It
/// stays *unconstructible* outside this crate: its only field is private and
/// its constructor [`RealEffects::new`] is crate-private, so the sole way to
/// obtain one is through [`production_effects`] / [`production_effects_concrete`],
/// which always wrap it in `PolicyEnforced` and require a policy.
pub struct RealEffects {
    /// Working directory for git subprocesses.
    ///
    /// `None` means the process CWD, which is the historical behaviour. Naming
    /// it matters because `git commit` is not scoped by its arguments: it acts
    /// on whatever repository the process happens to be standing in. A caller
    /// that means "commit the agent's workspace" and a caller that means
    /// "commit wherever I am" are different callers, and until this field
    /// existed there was no way to be the first one.
    git_dir: Option<std::path::PathBuf>,
    _private: (),
}

impl RealEffects {
    pub(crate) fn new() -> Self {
        Self {
            git_dir: None,
            _private: (),
        }
    }

    /// Scope git operations to `dir` instead of the process CWD.
    pub fn with_git_dir(dir: impl Into<std::path::PathBuf>) -> Self {
        Self {
            git_dir: Some(dir.into()),
            _private: (),
        }
    }

    /// The directory git subprocesses run in.
    ///
    /// Falls back to the process CWD (and to `.` if even that is unreadable),
    /// which is the behaviour every caller had before `git_dir` existed.
    fn git_cwd(&self) -> std::path::PathBuf {
        self.git_dir
            .clone()
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| std::path::PathBuf::from("."))
    }
}

impl FileEffect for RealEffects {
    fn read(&self, path: &Path, authority: Authority) -> Result<Vec<u8>, EffectError> {
        // The authority is consumed here and never handed back — this is the
        // point at which the right to read is spent.
        drop(authority);
        std::fs::read(path).map_err(|e| EffectError::Io(format!("{}: {e}", path.display())))
    }

    fn write(&self, path: &Path, content: &[u8], authority: Authority) -> Result<(), EffectError> {
        drop(authority);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| EffectError::Io(format!("{}: {e}", parent.display())))?;
        }
        std::fs::write(path, content)
            .map_err(|e| EffectError::Io(format!("{}: {e}", path.display())))
    }

    fn append(&self, path: &Path, content: &[u8], authority: Authority) -> Result<(), EffectError> {
        drop(authority);
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| EffectError::Io(format!("{}: {e}", path.display())))?;
        f.write_all(content)
            .map_err(|e| EffectError::Io(format!("{}: {e}", path.display())))
    }

    fn glob(&self, pattern: &str, authority: Authority) -> Result<Vec<PathBuf>, EffectError> {
        drop(authority);
        // Use regex-based glob matching against directory walk.
        // Convert glob syntax to regex: * → [^/]*, ** → .*, ? → [^/]
        let re_pattern = glob_to_regex(pattern);
        let re = regex::Regex::new(&re_pattern)
            .map_err(|e| EffectError::Io(format!("invalid glob pattern: {e}")))?;

        let base = if let Some(prefix) = literal_prefix(pattern) {
            PathBuf::from(prefix)
        } else {
            PathBuf::from(".")
        };

        let mut results = Vec::new();
        collect_matches(&base, &re, &mut results)
            .map_err(|e| EffectError::Io(format!("glob walk failed: {e}")))?;
        results.sort();
        Ok(results)
    }
}

impl WebEffect for RealEffects {
    fn fetch(&self, _url: &str, _authority: Authority) -> Result<Vec<u8>, EffectError> {
        // Synchronous HTTP is intentionally not implemented in portcullis-effects
        // to avoid pulling in a heavyweight HTTP client dependency. Callers that
        // need HTTP should use the nucleus-tool-proxy or inject a custom impl.
        Err(EffectError::NotImplemented(
            "web fetch requires nucleus-tool-proxy; inject a custom WebEffect impl",
        ))
    }

    fn search(
        &self,
        _query: &str,
        _authority: Authority,
    ) -> Result<Vec<SearchResult>, EffectError> {
        Err(EffectError::NotImplemented(
            "web search requires nucleus-tool-proxy; inject a custom WebEffect impl",
        ))
    }
}

/// **The check the effect functions never made.**
///
/// A `DischargedBundle` was taken as `_proof` — an unused type-level token — so
/// it established that "a preflight ran somewhere", never that "a preflight ran
/// for THIS action". A bundle legitimately earned for a workspace write was
/// structurally usable to authorise a shell spawn: the confused deputy in its
/// authorisation form.
///
/// Each effect knows which operation IT is, so it checks the bundle's scope
/// without the `ActionTerm` being threaded through its signature. This is the
/// binding the 2026 confused-deputy guidance recommends — approved operation,
/// approved scope — and the runtime form of a macaroon request-hash caveat.
///
/// The COMPILE-TIME form would make the bundle generic in the operation
/// (`DischargedBundle<RunBash>`) so a mismatch could not be written at all. That
/// is a refactor through every signature and caller; this closes the hole now.
pub(crate) fn require_scope(
    proof: &DischargedBundle,
    op: portcullis_core::Operation,
    sink: portcullis_core::SinkClass,
) -> Result<(), String> {
    if proof.authorizes(op, sink) {
        Ok(())
    } else {
        Err(format!(
            "discharge scope mismatch: bundle authorises {:?}/{:?}, this effect is {:?}/{:?}",
            proof.operation(),
            proof.sink_class(),
            op,
            sink
        ))
    }
}

impl ShellEffect for RealEffects {
    fn run(&self, cmd: &str, _authority: Authority) -> Result<ShellOutput, EffectError> {
        let words = shell_words::split(cmd)
            .map_err(|e| EffectError::Io(format!("shell parse failed: {e}")))?;
        if words.is_empty() {
            return Err(EffectError::Io("empty command".into()));
        }
        let output = std::process::Command::new(&words[0])
            .args(&words[1..])
            .output()
            .map_err(|e| EffectError::Io(format!("spawn failed: {e}")))?;
        Ok(ShellOutput {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }

    fn run_argv(
        &self,
        program: &str,
        args: &[String],
        cwd: &Path,
        stdin: Option<&[u8]>,
        allowed_env: &BTreeMap<String, String>,
        harden: Option<&(dyn Fn(&mut Command) + Send + Sync)>,
        authority: Authority,
    ) -> io::Result<Output> {
        // Spent here and dropped: the right to spawn is consumed at the spawn.
        let spent = authority
            .spend(
                portcullis_core::Operation::RunBash,
                portcullis_core::SinkClass::BashExec,
            )
            .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e.to_string()))?;
        drop(spent);
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
}

#[cfg(feature = "async")]
impl AsyncShellSpawnEffect for RealEffects {
    async fn run_argv_async(
        &self,
        program: &str,
        args: &[String],
        cwd: &Path,
        stdin: Option<&[u8]>,
        allowed_env: &BTreeMap<String, String>,
        harden: Option<&(dyn Fn(&mut tokio::process::Command) + Send + Sync)>,
        timeout: Option<std::time::Duration>,
        authority: Authority,
    ) -> io::Result<Output> {
        // Spent here and dropped: the right to spawn is consumed at the spawn.
        let spent = authority
            .spend(
                portcullis_core::Operation::RunBash,
                portcullis_core::SinkClass::BashExec,
            )
            .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e.to_string()))?;
        drop(spent);
        // Mirrors `Executor::run_with_timeout`'s tokio spawn.
        let mut cmd = tokio::process::Command::new(program);
        cmd.args(args)
            .current_dir(cwd)
            .env_clear() // Security: prevent secret leakage from parent
            .envs(allowed_env) // Only explicitly allowed vars
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        if stdin.is_some() {
            cmd.stdin(Stdio::piped());
        } else {
            cmd.stdin(Stdio::null());
        }

        if let Some(harden) = harden {
            harden(&mut cmd);
        }

        let mut child = cmd.spawn()?;
        if let Some(input) = stdin {
            if let Some(mut stdin_pipe) = child.stdin.take() {
                use tokio::io::AsyncWriteExt as _;
                stdin_pipe.write_all(input).await?;
                stdin_pipe.shutdown().await?;
            }
        }

        match timeout {
            Some(dur) => match tokio::time::timeout(dur, child.wait_with_output()).await {
                Ok(result) => result,
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("command timed out after {dur:?}"),
                )),
            },
            None => child.wait_with_output().await,
        }
    }
}

#[cfg(feature = "net")]
impl NetEffect for RealEffects {
    async fn fetch(
        &self,
        client: &reqwest::Client,
        _cap: NetCapability,
        method: reqwest::Method,
        url: reqwest::Url,
        headers: &[(String, String)],
        body: Option<Vec<u8>>,
        timeout: Option<std::time::Duration>,
        authority: Authority,
    ) -> Result<reqwest::Response, EffectError> {
        // Spent here and dropped: the right to egress is consumed at the send.
        let spent = authority
            .spend(
                portcullis_core::Operation::WebFetch,
                portcullis_core::SinkClass::HTTPEgress,
            )
            .map_err(|e| EffectError::Io(e.to_string()))?;
        drop(spent);
        // The relocated agent-egress send: build the request from the caller's
        // pieces on the caller's configured client, then perform the one raw
        // `reqwest …send()` that used to live in the tool-proxy handlers. This
        // is the only place that raw send may exist on the effect path.
        let mut request = client.request(method, url);
        for (key, value) in headers {
            request = request.header(key, value);
        }
        if let Some(body) = body {
            request = request.body(body);
        }
        if let Some(dur) = timeout {
            request = request.timeout(dur);
        }
        request
            .send()
            .await
            .map_err(|e| EffectError::Io(format!("request failed: {e}")))
    }
}

impl GitEffect for RealEffects {
    fn commit(&self, message: &str, _authority: Authority) -> Result<String, EffectError> {
        // Stage all tracked modifications and commit.
        let add = std::process::Command::new("git")
            .args(["add", "-u"])
            .current_dir(self.git_cwd())
            .output()
            .map_err(|e| EffectError::Io(format!("git add: {e}")))?;
        if !add.status.success() {
            return Err(EffectError::CommandFailed {
                exit_code: add.status.code(),
                stderr: String::from_utf8_lossy(&add.stderr).into_owned(),
            });
        }
        let commit = std::process::Command::new("git")
            .args(["commit", "-m", message])
            .current_dir(self.git_cwd())
            .output()
            .map_err(|e| EffectError::Io(format!("git commit: {e}")))?;
        if !commit.status.success() {
            return Err(EffectError::CommandFailed {
                exit_code: commit.status.code(),
                stderr: String::from_utf8_lossy(&commit.stderr).into_owned(),
            });
        }
        // Extract the commit hash from the output (first 7 chars of the OID line).
        let out = String::from_utf8_lossy(&commit.stdout).into_owned();
        Ok(out.trim().to_string())
    }

    fn push(&self, remote: &str, branch: &str, _authority: Authority) -> Result<(), EffectError> {
        let output = std::process::Command::new("git")
            .args(["push", remote, branch])
            .current_dir(self.git_cwd())
            .output()
            .map_err(|e| EffectError::Io(format!("git push: {e}")))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(EffectError::CommandFailed {
                exit_code: output.status.code(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            })
        }
    }
}

impl AgentSpawnEffect for RealEffects {
    fn spawn(
        &self,
        _endpoint: &str,
        _term_json: &str,
        _authority: Authority,
    ) -> Result<String, EffectError> {
        Err(EffectError::NotImplemented(
            "agent spawn not yet implemented; use nucleus-client for remote dispatch",
        ))
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PolicyEnforced<E> wrapper
// ═══════════════════════════════════════════════════════════════════════════

/// Wraps an effect implementation and checks the capability policy before
/// delegating every call. This is the only way to obtain a callable effect.
///
/// Construct via [`production_effects`] — the only public constructor.
pub struct PolicyEnforced<E> {
    inner: E,
    policy: CapabilityLattice,
    /// Every mediation decision this handler makes, hash-chained.
    ///
    /// Always present, never optional: an effect handler that could be built
    /// without a log would make "every effect is witnessed" a deployment
    /// question rather than a property of the type.
    receipts: Arc<crate::receipt::ReceiptLog>,
}

impl<E> PolicyEnforced<E> {
    /// Expose the underlying policy for inspection.
    pub fn policy(&self) -> &CapabilityLattice {
        &self.policy
    }

    /// The chain of mediation decisions made through this handler.
    pub fn receipts(&self) -> &crate::receipt::ReceiptLog {
        &self.receipts
    }

    /// Hand an authority the log it should record its spend against.
    ///
    /// The mediation layer owns the log and the authority owns the spend, so the
    /// witness has to be attached on the way past. Every method that accepts an
    /// `Authority` routes it through here — the ten via [`gate`](Self::gate), the
    /// three that spend further down by calling this directly.
    fn witnessed(&self, authority: Authority) -> Authority {
        authority.witnessed_by(std::sync::Arc::clone(&self.receipts))
    }

    /// Record a refusal the authority never got far enough to record itself.
    ///
    /// The capability lattice is checked before the spend, so on that path the
    /// authority is dropped unspent and no receipt comes from `spend`.
    fn record_policy_denial(
        &self,
        op: portcullis_core::Operation,
        sink: portcullis_core::SinkClass,
    ) {
        self.receipts
            .append(op, sink, crate::receipt::EffectOutcome::DeniedByPolicy);
    }

    /// Check the capability, then spend the authority.
    ///
    /// The `Allowed` and `DeniedByScope` receipts are **not** written here — they
    /// are written by [`Authority::spend`], which is the only way to consume an
    /// authority and therefore the one place the record cannot be skipped. This
    /// function only has to add the branch `spend` never sees: the capability
    /// lattice refusing before any spend happens.
    fn gate(
        &self,
        level: CapabilityLevel,
        capability: &str,
        authority: Authority,
        op: portcullis_core::Operation,
        sink: portcullis_core::SinkClass,
    ) -> Result<Authority, EffectError> {
        if let Err(e) = self.require(level, capability) {
            self.record_policy_denial(op, sink);
            return Err(e);
        }
        match self.witnessed(authority).spend(op, sink) {
            Ok(bundle) => Ok(Authority::new(bundle)),
            Err(e) => Err(EffectError::PolicyDenied(e.to_string())),
        }
    }

    fn require(&self, level: CapabilityLevel, capability: &str) -> Result<(), EffectError> {
        if level == CapabilityLevel::Never {
            Err(EffectError::PolicyDenied(format!(
                "capability {capability} is Never in policy"
            )))
        } else {
            Ok(())
        }
    }
}

impl<E: FileEffect> FileEffect for PolicyEnforced<E> {
    fn read(&self, path: &Path, authority: Authority) -> Result<Vec<u8>, EffectError> {
        let authority = self.gate(
            self.policy.read_files,
            "read_files",
            authority,
            portcullis_core::Operation::ReadFiles,
            portcullis_core::SinkClass::AuditLogAppend,
        )?;
        self.inner.read(path, authority)
    }

    fn write(&self, path: &Path, content: &[u8], authority: Authority) -> Result<(), EffectError> {
        let authority = self.gate(
            self.policy.write_files,
            "write_files",
            authority,
            portcullis_core::Operation::WriteFiles,
            portcullis_core::SinkClass::WorkspaceWrite,
        )?;
        self.inner.write(path, content, authority)
    }

    fn append(&self, path: &Path, content: &[u8], authority: Authority) -> Result<(), EffectError> {
        let authority = self.gate(
            self.policy.write_files,
            "write_files (append)",
            authority,
            portcullis_core::Operation::WriteFiles,
            portcullis_core::SinkClass::WorkspaceWrite,
        )?;
        self.inner.append(path, content, authority)
    }

    fn glob(&self, pattern: &str, authority: Authority) -> Result<Vec<PathBuf>, EffectError> {
        let authority = self.gate(
            self.policy.glob_search,
            "glob_search",
            authority,
            portcullis_core::Operation::GlobSearch,
            portcullis_core::SinkClass::AuditLogAppend,
        )?;
        self.inner.glob(pattern, authority)
    }
}

impl<E: WebEffect> WebEffect for PolicyEnforced<E> {
    fn fetch(&self, url: &str, authority: Authority) -> Result<Vec<u8>, EffectError> {
        let authority = self.gate(
            self.policy.web_fetch,
            "web_fetch",
            authority,
            portcullis_core::Operation::WebFetch,
            portcullis_core::SinkClass::HTTPEgress,
        )?;
        self.inner.fetch(url, authority)
    }

    fn search(&self, query: &str, authority: Authority) -> Result<Vec<SearchResult>, EffectError> {
        let authority = self.gate(
            self.policy.web_search,
            "web_search",
            authority,
            portcullis_core::Operation::WebSearch,
            portcullis_core::SinkClass::HTTPEgress,
        )?;
        self.inner.search(query, authority)
    }
}

impl<E: ShellEffect> ShellEffect for PolicyEnforced<E> {
    fn run(&self, cmd: &str, authority: Authority) -> Result<ShellOutput, EffectError> {
        let authority = self.gate(
            self.policy.run_bash,
            "run_bash",
            authority,
            portcullis_core::Operation::RunBash,
            portcullis_core::SinkClass::BashExec,
        )?;
        self.inner.run(cmd, authority)
    }

    fn run_argv(
        &self,
        program: &str,
        args: &[String],
        cwd: &Path,
        stdin: Option<&[u8]>,
        allowed_env: &BTreeMap<String, String>,
        harden: Option<&(dyn Fn(&mut Command) + Send + Sync)>,
        authority: Authority,
    ) -> io::Result<Output> {
        // Preserve the sealed policy gate for the structured spawn too. The
        // authority itself is spent further down, inside `RealEffects`, so the
        // witness is attached here and travels with it.
        if let Err(e) = self.require(self.policy.run_bash, "run_bash") {
            self.record_policy_denial(
                portcullis_core::Operation::RunBash,
                portcullis_core::SinkClass::BashExec,
            );
            return Err(policy_denied_io(e));
        }
        self.inner.run_argv(
            program,
            args,
            cwd,
            stdin,
            allowed_env,
            harden,
            self.witnessed(authority),
        )
    }
}

#[cfg(feature = "async")]
impl<E: AsyncShellSpawnEffect> AsyncShellSpawnEffect for PolicyEnforced<E> {
    async fn run_argv_async(
        &self,
        program: &str,
        args: &[String],
        cwd: &Path,
        stdin: Option<&[u8]>,
        allowed_env: &BTreeMap<String, String>,
        harden: Option<&(dyn Fn(&mut tokio::process::Command) + Send + Sync)>,
        timeout: Option<std::time::Duration>,
        authority: Authority,
    ) -> io::Result<Output> {
        if let Err(e) = self.require(self.policy.run_bash, "run_bash") {
            self.record_policy_denial(
                portcullis_core::Operation::RunBash,
                portcullis_core::SinkClass::BashExec,
            );
            return Err(policy_denied_io(e));
        }
        self.inner
            .run_argv_async(
                program,
                args,
                cwd,
                stdin,
                allowed_env,
                harden,
                timeout,
                self.witnessed(authority),
            )
            .await
    }
}

#[cfg(feature = "net")]
impl<E: NetEffect> NetEffect for PolicyEnforced<E> {
    async fn fetch(
        &self,
        client: &reqwest::Client,
        cap: NetCapability,
        method: reqwest::Method,
        url: reqwest::Url,
        headers: &[(String, String)],
        body: Option<Vec<u8>>,
        timeout: Option<std::time::Duration>,
        authority: Authority,
    ) -> Result<reqwest::Response, EffectError> {
        // Preserve the sealed policy gate for the egress too — mirror of the
        // `run_bash` gate on the structured spawn. The governing capability
        // depends on which agent net op this is (web_fetch vs web_search).
        let governing = match cap {
            NetCapability::WebFetch => self.require(self.policy.web_fetch, "web_fetch"),
            NetCapability::WebSearch => self.require(self.policy.web_search, "web_search"),
        };
        if let Err(e) = governing {
            // Recorded against the pair the spend below would have used, which
            // is `(WebFetch, HTTPEgress)` for both capabilities — the egress is
            // the same sink whichever agent op reached for it.
            self.record_policy_denial(
                portcullis_core::Operation::WebFetch,
                portcullis_core::SinkClass::HTTPEgress,
            );
            return Err(e);
        }
        self.inner
            .fetch(
                client,
                cap,
                method,
                url,
                headers,
                body,
                timeout,
                self.witnessed(authority),
            )
            .await
    }
}

impl<E: GitEffect> GitEffect for PolicyEnforced<E> {
    fn commit(&self, message: &str, authority: Authority) -> Result<String, EffectError> {
        let authority = self.gate(
            self.policy.git_commit,
            "git_commit",
            authority,
            portcullis_core::Operation::GitCommit,
            portcullis_core::SinkClass::GitCommit,
        )?;
        self.inner.commit(message, authority)
    }

    fn push(&self, remote: &str, branch: &str, authority: Authority) -> Result<(), EffectError> {
        let authority = self.gate(
            self.policy.git_push,
            "git_push",
            authority,
            portcullis_core::Operation::GitPush,
            portcullis_core::SinkClass::GitPush,
        )?;
        self.inner.push(remote, branch, authority)
    }
}

impl<E: AgentSpawnEffect> AgentSpawnEffect for PolicyEnforced<E> {
    fn spawn(
        &self,
        endpoint: &str,
        term_json: &str,
        authority: Authority,
    ) -> Result<String, EffectError> {
        let authority = self.gate(
            self.policy.spawn_agent,
            "spawn_agent",
            authority,
            portcullis_core::Operation::SpawnAgent,
            portcullis_core::SinkClass::AgentSpawn,
        )?;
        self.inner.spawn(endpoint, term_json, authority)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Public constructor — the only way to obtain a real PolicyEnforced<RealEffects>
// ═══════════════════════════════════════════════════════════════════════════

/// Construct the production effect handler.
///
/// This is the **only public constructor** for I/O-capable effects.
/// `RealEffects` is not constructible by callers directly; it can only
/// be obtained wrapped in `PolicyEnforced`, ensuring policy is always checked.
/// The concrete return type is intentionally opaque — callers interact through
/// the effect traits, never through the underlying implementation type.
///
/// # Example
///
/// ```rust
/// use portcullis_effects::{production_effects, FileEffect};
/// # use portcullis_effects::authority::Authority;
/// # use portcullis_core::discharge::test_helpers::bundle_for;
/// # use portcullis_core::{Operation, SinkClass};
/// # let read_authority = || Authority::new(
/// #     bundle_for(Operation::ReadFiles, SinkClass::AuditLogAppend));
/// use portcullis_core::{CapabilityLattice, CapabilityLevel};
///
/// let policy = CapabilityLattice {
///     read_files: CapabilityLevel::Always,
///     ..CapabilityLattice::bottom()
/// };
/// let fx = production_effects(policy);
/// // fx implements FileEffect, WebEffect, ShellEffect, GitEffect, AgentSpawnEffect
/// // The lattice is checked at every call; the `Authority` carries the eight
/// // obligations and is spent by the call.
/// let result = fx.read(std::path::Path::new("Cargo.toml"), read_authority());
/// // May succeed or fail depending on filesystem; policy gate is open.
/// let _ = result;
/// ```
pub fn production_effects(
    policy: CapabilityLattice,
) -> impl FileEffect + WebEffect + ShellEffect + GitEffect + AgentSpawnEffect {
    production_effects_concrete(policy)
}

/// Returns the **concrete** `PolicyEnforced<RealEffects>` handle (rather than the
/// opaque `impl Trait` of [`production_effects`]).
///
/// Consumers that must reach the async spawn ([`AsyncShellSpawnEffect::run_argv_async`],
/// behind `feature = "async"`) need a concrete type: that trait has an `async fn`
/// and so is **not** dyn-compatible (`Arc<dyn AsyncShellSpawnEffect>` is `E0038`).
/// The concrete handle impls *both* `ShellEffect` (sync) and, under the `async`
/// feature, `AsyncShellSpawnEffect` — one value serves both spawn paths while
/// preserving the `PolicyEnforced` capability gate on every call. `RealEffects`
/// remains unconstructible outside this crate, so policy enforcement cannot be
/// bypassed.
pub fn production_effects_concrete(policy: CapabilityLattice) -> PolicyEnforced<RealEffects> {
    PolicyEnforced {
        inner: RealEffects::new(),
        policy,
        receipts: Arc::new(crate::receipt::ReceiptLog::new()),
    }
}

/// As [`production_effects_concrete`], with git operations scoped to `git_dir`
/// rather than the process working directory.
pub fn production_effects_in(
    policy: CapabilityLattice,
    git_dir: impl Into<std::path::PathBuf>,
) -> PolicyEnforced<RealEffects> {
    PolicyEnforced {
        inner: RealEffects::with_git_dir(git_dir),
        policy,
        receipts: Arc::new(crate::receipt::ReceiptLog::new()),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Test implementations
// ═══════════════════════════════════════════════════════════════════════════

/// A call record captured by [`RecordingEffects`].
#[derive(Debug, Clone)]
pub struct EffectCall {
    pub kind: &'static str,
    pub detail: String,
}

/// Records all effect calls without performing real I/O.
///
/// Returns configurable stub responses. Default: empty success responses.
///
/// # Example
///
/// ```rust
/// use portcullis_effects::{RecordingEffects, FileEffect};
/// # use portcullis_effects::authority::Authority;
/// # use portcullis_core::discharge::test_helpers::bundle_for;
/// # use portcullis_core::{Operation, SinkClass};
/// # let read_authority = || Authority::new(
/// #     bundle_for(Operation::ReadFiles, SinkClass::AuditLogAppend));
///
/// let fx = RecordingEffects::new();
/// let _ = fx.read(std::path::Path::new("src/main.rs"), read_authority());
/// assert_eq!(fx.calls().len(), 1);
/// assert_eq!(fx.calls()[0].kind, "read");
/// ```
pub struct RecordingEffects {
    calls: Arc<Mutex<Vec<EffectCall>>>,
    file_read_response: Vec<u8>,
}

impl RecordingEffects {
    pub fn new() -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            file_read_response: Vec::new(),
        }
    }

    /// Pre-configure the bytes returned by `read()`.
    pub fn with_file_content(mut self, content: impl Into<Vec<u8>>) -> Self {
        self.file_read_response = content.into();
        self
    }

    /// Return a snapshot of all calls recorded so far.
    pub fn calls(&self) -> Vec<EffectCall> {
        self.calls.lock().unwrap().clone()
    }

    fn record(&self, kind: &'static str, detail: impl Into<String>) {
        self.calls.lock().unwrap().push(EffectCall {
            kind,
            detail: detail.into(),
        });
    }
}

impl Default for RecordingEffects {
    fn default() -> Self {
        Self::new()
    }
}

impl FileEffect for RecordingEffects {
    fn read(&self, path: &Path, _authority: Authority) -> Result<Vec<u8>, EffectError> {
        self.record("read", path.display().to_string());
        Ok(self.file_read_response.clone())
    }

    fn write(&self, path: &Path, content: &[u8], _authority: Authority) -> Result<(), EffectError> {
        self.record(
            "write",
            format!("{}({} bytes)", path.display(), content.len()),
        );
        Ok(())
    }

    fn append(
        &self,
        path: &Path,
        content: &[u8],
        _authority: Authority,
    ) -> Result<(), EffectError> {
        self.record(
            "append",
            format!("{}(+{} bytes)", path.display(), content.len()),
        );
        Ok(())
    }

    fn glob(&self, pattern: &str, _authority: Authority) -> Result<Vec<PathBuf>, EffectError> {
        self.record("glob", pattern);
        Ok(Vec::new())
    }
}

impl WebEffect for RecordingEffects {
    fn fetch(&self, url: &str, _authority: Authority) -> Result<Vec<u8>, EffectError> {
        self.record("fetch", url);
        Ok(Vec::new())
    }

    fn search(&self, query: &str, _authority: Authority) -> Result<Vec<SearchResult>, EffectError> {
        self.record("search", query);
        Ok(Vec::new())
    }
}

impl ShellEffect for RecordingEffects {
    fn run(&self, cmd: &str, _authority: Authority) -> Result<ShellOutput, EffectError> {
        self.record("run", cmd);
        Ok(ShellOutput {
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit_code: 0,
        })
    }

    fn run_argv(
        &self,
        program: &str,
        args: &[String],
        cwd: &Path,
        _stdin: Option<&[u8]>,
        _allowed_env: &BTreeMap<String, String>,
        _harden: Option<&(dyn Fn(&mut Command) + Send + Sync)>,
        authority: Authority,
    ) -> io::Result<Output> {
        // Spent here for the same reason `RealEffects::run_argv` spends here:
        // this is one of the three methods `PolicyEnforced` forwards without
        // spending, so the consumption happens in the inner effect. A double
        // that dropped the authority instead would silently diverge from the
        // real implementation on the exact property the receipt tests check.
        drop(
            authority
                .spend(
                    portcullis_core::Operation::RunBash,
                    portcullis_core::SinkClass::BashExec,
                )
                .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e.to_string()))?,
        );
        self.record(
            "run_argv",
            format!("{program} {args:?} @ {}", cwd.display()),
        );
        Ok(empty_success_output())
    }
}

#[cfg(feature = "async")]
impl AsyncShellSpawnEffect for RecordingEffects {
    async fn run_argv_async(
        &self,
        program: &str,
        args: &[String],
        cwd: &Path,
        _stdin: Option<&[u8]>,
        _allowed_env: &BTreeMap<String, String>,
        _harden: Option<&(dyn Fn(&mut tokio::process::Command) + Send + Sync)>,
        _timeout: Option<std::time::Duration>,
        authority: Authority,
    ) -> io::Result<Output> {
        // Mirrors `RealEffects::run_argv_async` — see `run_argv` above.
        drop(
            authority
                .spend(
                    portcullis_core::Operation::RunBash,
                    portcullis_core::SinkClass::BashExec,
                )
                .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e.to_string()))?,
        );
        self.record(
            "run_argv_async",
            format!("{program} {args:?} @ {}", cwd.display()),
        );
        Ok(empty_success_output())
    }
}

/// Records the egress and spends the authority, without ever opening a socket.
///
/// `RealEffects::fetch` is the only other `NetEffect`, and it performs a real
/// send — so without this double the third of the three deferred-spend methods
/// could not be covered by a receipt test at all.
/// Test-only, so the production dependency surface of this crate is unchanged:
/// building a `reqwest::Response` from nothing needs `http` directly, and that
/// is a dev-dependency.
#[cfg(all(test, feature = "net"))]
impl NetEffect for RecordingEffects {
    async fn fetch(
        &self,
        _client: &reqwest::Client,
        _cap: NetCapability,
        method: reqwest::Method,
        url: reqwest::Url,
        _headers: &[(String, String)],
        _body: Option<Vec<u8>>,
        _timeout: Option<std::time::Duration>,
        authority: Authority,
    ) -> Result<reqwest::Response, EffectError> {
        // Mirrors `RealEffects::fetch`: the egress right is consumed at the send.
        drop(
            authority
                .spend(
                    portcullis_core::Operation::WebFetch,
                    portcullis_core::SinkClass::HTTPEgress,
                )
                .map_err(|e| EffectError::Io(e.to_string()))?,
        );
        self.record("net_fetch", format!("{method} {url}"));
        Ok(reqwest::Response::from(http::Response::new("")))
    }
}

impl GitEffect for RecordingEffects {
    fn commit(&self, message: &str, _authority: Authority) -> Result<String, EffectError> {
        self.record("commit", message);
        Ok("deadbeef".to_string())
    }

    fn push(&self, remote: &str, branch: &str, _authority: Authority) -> Result<(), EffectError> {
        self.record("push", format!("{remote}/{branch}"));
        Ok(())
    }
}

impl AgentSpawnEffect for RecordingEffects {
    fn spawn(
        &self,
        endpoint: &str,
        term_json: &str,
        _authority: Authority,
    ) -> Result<String, EffectError> {
        self.record("spawn", format!("{endpoint}: {term_json}"));
        Ok("decision:allow".to_string())
    }
}

/// Denies every effect call.
///
/// Useful for testing that code paths handle denial correctly.
///
/// # Example
///
/// ```rust
/// use portcullis_effects::{DenyAllEffects, FileEffect};
/// # use portcullis_effects::authority::Authority;
/// # use portcullis_core::discharge::test_helpers::bundle_for;
/// # use portcullis_core::{Operation, SinkClass};
/// # let read_authority = || Authority::new(
/// #     bundle_for(Operation::ReadFiles, SinkClass::AuditLogAppend));
///
/// let fx = DenyAllEffects;
/// assert!(fx.read(std::path::Path::new("any.txt"), read_authority()).is_err());
/// ```
pub struct DenyAllEffects;

impl FileEffect for DenyAllEffects {
    fn read(&self, path: &Path, _authority: Authority) -> Result<Vec<u8>, EffectError> {
        Err(EffectError::PolicyDenied(format!(
            "read denied: {}",
            path.display()
        )))
    }
    fn write(
        &self,
        path: &Path,
        _content: &[u8],
        _authority: Authority,
    ) -> Result<(), EffectError> {
        Err(EffectError::PolicyDenied(format!(
            "write denied: {}",
            path.display()
        )))
    }
    fn append(
        &self,
        path: &Path,
        _content: &[u8],
        _authority: Authority,
    ) -> Result<(), EffectError> {
        Err(EffectError::PolicyDenied(format!(
            "append denied: {}",
            path.display()
        )))
    }
    fn glob(&self, pattern: &str, _authority: Authority) -> Result<Vec<PathBuf>, EffectError> {
        Err(EffectError::PolicyDenied(format!("glob denied: {pattern}")))
    }
}

impl WebEffect for DenyAllEffects {
    fn fetch(&self, url: &str, _authority: Authority) -> Result<Vec<u8>, EffectError> {
        Err(EffectError::PolicyDenied(format!("fetch denied: {url}")))
    }
    fn search(&self, query: &str, _authority: Authority) -> Result<Vec<SearchResult>, EffectError> {
        Err(EffectError::PolicyDenied(format!("search denied: {query}")))
    }
}

impl ShellEffect for DenyAllEffects {
    fn run(&self, cmd: &str, _authority: Authority) -> Result<ShellOutput, EffectError> {
        Err(EffectError::PolicyDenied(format!("shell denied: {cmd}")))
    }

    fn run_argv(
        &self,
        program: &str,
        _args: &[String],
        _cwd: &Path,
        _stdin: Option<&[u8]>,
        _allowed_env: &BTreeMap<String, String>,
        _harden: Option<&(dyn Fn(&mut Command) + Send + Sync)>,
        _authority: Authority,
    ) -> io::Result<Output> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("shell denied: {program}"),
        ))
    }
}

#[cfg(feature = "async")]
impl AsyncShellSpawnEffect for DenyAllEffects {
    async fn run_argv_async(
        &self,
        program: &str,
        _args: &[String],
        _cwd: &Path,
        _stdin: Option<&[u8]>,
        _allowed_env: &BTreeMap<String, String>,
        _harden: Option<&(dyn Fn(&mut tokio::process::Command) + Send + Sync)>,
        _timeout: Option<std::time::Duration>,
        _authority: Authority,
    ) -> io::Result<Output> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("shell denied: {program}"),
        ))
    }
}

impl GitEffect for DenyAllEffects {
    fn commit(&self, message: &str, _authority: Authority) -> Result<String, EffectError> {
        Err(EffectError::PolicyDenied(format!(
            "git commit denied: {message}"
        )))
    }
    fn push(&self, remote: &str, branch: &str, _authority: Authority) -> Result<(), EffectError> {
        Err(EffectError::PolicyDenied(format!(
            "git push denied: {remote}/{branch}"
        )))
    }
}

impl AgentSpawnEffect for DenyAllEffects {
    fn spawn(
        &self,
        endpoint: &str,
        _term_json: &str,
        _authority: Authority,
    ) -> Result<String, EffectError> {
        Err(EffectError::PolicyDenied(format!(
            "spawn denied: {endpoint}"
        )))
    }
}

/// Allows only files and URLs in an explicit allowlist.
///
/// All other paths and URLs are denied with `EffectError::PolicyDenied`.
///
/// # Example
///
/// ```rust
/// use portcullis_effects::{AllowListEffects, FileEffect};
/// # use portcullis_effects::authority::Authority;
/// # use portcullis_core::discharge::test_helpers::bundle_for;
/// # use portcullis_core::{Operation, SinkClass};
/// # let read_authority = || Authority::new(
/// #     bundle_for(Operation::ReadFiles, SinkClass::AuditLogAppend));
///
/// let fx = AllowListEffects::new()
///     .allow_path("/workspace/src");
/// assert!(fx.read(std::path::Path::new("/workspace/src/main.rs"), read_authority()).is_ok());
/// assert!(fx.read(std::path::Path::new("/etc/passwd"), read_authority()).is_err());
/// ```
pub struct AllowListEffects {
    allowed_path_prefixes: Vec<PathBuf>,
    allowed_url_prefixes: Vec<String>,
    file_read_response: Vec<u8>,
}

impl AllowListEffects {
    pub fn new() -> Self {
        Self {
            allowed_path_prefixes: Vec::new(),
            allowed_url_prefixes: Vec::new(),
            file_read_response: Vec::new(),
        }
    }

    pub fn allow_path(mut self, prefix: impl Into<PathBuf>) -> Self {
        self.allowed_path_prefixes.push(prefix.into());
        self
    }

    pub fn allow_url(mut self, prefix: impl Into<String>) -> Self {
        self.allowed_url_prefixes.push(prefix.into());
        self
    }

    pub fn with_file_content(mut self, content: impl Into<Vec<u8>>) -> Self {
        self.file_read_response = content.into();
        self
    }

    fn check_path(&self, path: &Path) -> Result<(), EffectError> {
        let allowed = self
            .allowed_path_prefixes
            .iter()
            .any(|p| path.starts_with(p));
        if allowed {
            Ok(())
        } else {
            Err(EffectError::PathViolation(format!(
                "{} is outside all allowed prefixes",
                path.display()
            )))
        }
    }

    fn check_url(&self, url: &str) -> Result<(), EffectError> {
        let allowed = self
            .allowed_url_prefixes
            .iter()
            .any(|p| url.starts_with(p.as_str()));
        if allowed {
            Ok(())
        } else {
            Err(EffectError::PolicyDenied(format!(
                "{url} is outside allowed URL prefixes"
            )))
        }
    }
}

impl Default for AllowListEffects {
    fn default() -> Self {
        Self::new()
    }
}

impl FileEffect for AllowListEffects {
    fn read(&self, path: &Path, _authority: Authority) -> Result<Vec<u8>, EffectError> {
        self.check_path(path)?;
        Ok(self.file_read_response.clone())
    }

    fn write(
        &self,
        path: &Path,
        _content: &[u8],
        _authority: Authority,
    ) -> Result<(), EffectError> {
        self.check_path(path)
    }

    fn append(
        &self,
        path: &Path,
        _content: &[u8],
        _authority: Authority,
    ) -> Result<(), EffectError> {
        self.check_path(path)
    }

    fn glob(&self, _pattern: &str, _authority: Authority) -> Result<Vec<PathBuf>, EffectError> {
        Ok(Vec::new())
    }
}

impl WebEffect for AllowListEffects {
    fn fetch(&self, url: &str, _authority: Authority) -> Result<Vec<u8>, EffectError> {
        self.check_url(url)?;
        Ok(Vec::new())
    }

    fn search(
        &self,
        _query: &str,
        _authority: Authority,
    ) -> Result<Vec<SearchResult>, EffectError> {
        Ok(Vec::new())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Internal spawn helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Map a policy-denial [`EffectError`] onto the `io::Error` surface used by the
/// structured spawn methods (`run_argv` / `run_argv_async` return `io::Result`).
fn policy_denied_io(err: EffectError) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, err.to_string())
}

/// A synthetic successful [`Output`] with empty streams — used by the mock
/// [`ShellEffect`] impls that record but do not spawn a real process.
fn empty_success_output() -> Output {
    Output {
        status: exit_status_zero(),
        stdout: Vec::new(),
        stderr: Vec::new(),
    }
}

#[cfg(unix)]
fn exit_status_zero() -> std::process::ExitStatus {
    use std::os::unix::process::ExitStatusExt as _;
    std::process::ExitStatus::from_raw(0)
}

#[cfg(windows)]
fn exit_status_zero() -> std::process::ExitStatus {
    use std::os::windows::process::ExitStatusExt as _;
    std::process::ExitStatus::from_raw(0)
}

// ═══════════════════════════════════════════════════════════════════════════
// Internal glob helpers
// ═══════════════════════════════════════════════════════════════════════════

fn glob_to_regex(pattern: &str) -> String {
    let mut re = String::from("^");
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '*' if chars.peek() == Some(&'*') => {
                chars.next();
                re.push_str(".*");
            }
            '*' => re.push_str("[^/]*"),
            '?' => re.push_str("[^/]"),
            '.' | '+' | '^' | '$' | '{' | '}' | '(' | ')' | '|' | '[' | ']' | '\\' => {
                re.push('\\');
                re.push(c);
            }
            _ => re.push(c),
        }
    }
    re.push('$');
    re
}

fn literal_prefix(pattern: &str) -> Option<&str> {
    let end = pattern.find(['*', '?', '['])?;
    let prefix = &pattern[..end];
    let dir_end = prefix.rfind('/')?;
    Some(&prefix[..dir_end])
}

fn collect_matches(
    dir: &Path,
    re: &regex::Regex,
    results: &mut Vec<PathBuf>,
) -> std::io::Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let path_str = path.to_string_lossy();
        if re.is_match(&path_str) {
            results.push(path.clone());
        }
        if path.is_dir() {
            collect_matches(&path, re, results)?;
        }
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// An authority scoped to a file read.
    fn read_auth() -> Authority {
        Authority::new(portcullis_core::discharge::test_helpers::bundle_for(
            portcullis_core::Operation::ReadFiles,
            portcullis_core::SinkClass::AuditLogAppend,
        ))
    }

    /// An authority scoped to a workspace write (also governs `append`).
    fn write_auth() -> Authority {
        Authority::new(portcullis_core::discharge::test_helpers::bundle_for(
            portcullis_core::Operation::WriteFiles,
            portcullis_core::SinkClass::WorkspaceWrite,
        ))
    }

    /// An authority scoped to a glob search.
    fn glob_auth() -> Authority {
        Authority::new(portcullis_core::discharge::test_helpers::bundle_for(
            portcullis_core::Operation::GlobSearch,
            portcullis_core::SinkClass::AuditLogAppend,
        ))
    }

    /// Authorities for the remaining effect traits, each scoped to the one
    /// `(Operation, SinkClass)` pair its trait method spends on.
    fn auth_for(op: portcullis_core::Operation, sink: portcullis_core::SinkClass) -> Authority {
        Authority::new(portcullis_core::discharge::test_helpers::bundle_for(
            op, sink,
        ))
    }
    fn fetch_auth() -> Authority {
        auth_for(
            portcullis_core::Operation::WebFetch,
            portcullis_core::SinkClass::HTTPEgress,
        )
    }
    fn search_auth() -> Authority {
        auth_for(
            portcullis_core::Operation::WebSearch,
            portcullis_core::SinkClass::HTTPEgress,
        )
    }
    fn shell_auth() -> Authority {
        auth_for(
            portcullis_core::Operation::RunBash,
            portcullis_core::SinkClass::BashExec,
        )
    }
    fn commit_auth() -> Authority {
        auth_for(
            portcullis_core::Operation::GitCommit,
            portcullis_core::SinkClass::GitCommit,
        )
    }
    fn push_auth() -> Authority {
        auth_for(
            portcullis_core::Operation::GitPush,
            portcullis_core::SinkClass::GitPush,
        )
    }
    fn spawn_auth() -> Authority {
        auth_for(
            portcullis_core::Operation::SpawnAgent,
            portcullis_core::SinkClass::AgentSpawn,
        )
    }

    // ── Uniform mediation on FileEffect (B1/B2) ────────────────────────────

    /// The gap this cutover closes: before it, `FileEffect::write` took no
    /// obligation token at all and was gated only by `write_files != Never`, so
    /// none of the eight obligations reached a file write. Now the write spends
    /// an authority, and one earned for a read will not pay for it.
    #[test]
    fn a_read_authority_will_not_pay_for_a_write_at_the_effect_layer() {
        let fx = production_effects_concrete(CapabilityLattice {
            read_files: CapabilityLevel::Always,
            write_files: CapabilityLevel::Always,
            ..CapabilityLattice::bottom()
        });
        let err = fx
            .write(Path::new("/tmp/nucleus-scope-test"), b"x", read_auth())
            .expect_err("a read authority must not pay for a write");
        assert!(
            matches!(err, EffectError::PolicyDenied(ref m) if m.contains("scope")),
            "expected a scope denial, got: {err:?}"
        );
    }

    /// …and the lattice gate is NOT what refuses it. `write_files` is `Always`
    /// above, so a pass here would mean the coarse capability was doing the work
    /// and the obligations still were not.
    #[test]
    fn the_scope_refusal_is_not_the_lattice_gate() {
        let fx = production_effects_concrete(CapabilityLattice {
            write_files: CapabilityLevel::Always,
            ..CapabilityLattice::bottom()
        });
        // Correctly scoped: passes the scope check, reaches the real effect.
        let ok = fx.write(Path::new("/tmp/nucleus-scope-test-ok"), b"x", write_auth());
        assert!(
            !matches!(&ok, Err(EffectError::PolicyDenied(m)) if m.contains("scope")),
            "a correctly-scoped write must not be refused on scope: {ok:?}"
        );
        let _ = std::fs::remove_file("/tmp/nucleus-scope-test-ok");
    }

    /// `git push` is the highest-consequence sink in the system and was gated
    /// only by `git_push != Never`. A commit authority must not pay for it —
    /// the escalation `scope_admits_no_escalation` names on the Lean side.
    ///
    /// Uses `RecordingEffects` as the inner impl: a correctly-scoped push
    /// through `RealEffects` would run a real `git push`.
    #[test]
    fn a_commit_authority_will_not_pay_for_a_push() {
        let fx = PolicyEnforced {
            inner: RecordingEffects::new(),
            receipts: Arc::new(crate::receipt::ReceiptLog::new()),
            policy: CapabilityLattice {
                git_commit: CapabilityLevel::Always,
                git_push: CapabilityLevel::Always,
                ..CapabilityLattice::bottom()
            },
        };
        let err = fx
            .push("origin", "main", commit_auth())
            .expect_err("a commit authority must not pay for a push");
        assert!(
            matches!(err, EffectError::PolicyDenied(ref m) if m.contains("scope")),
            "expected a scope denial, got: {err:?}"
        );
        assert!(
            fx.inner.calls().is_empty(),
            "the refusal must precede the effect, but the inner impl was called"
        );
    }

    /// Every newly-mediated method refuses an authority earned elsewhere, and
    /// refuses it BEFORE reaching the inner effect. `git_push` above is the
    /// headline; this pins the same property across the rest of the surface.
    #[test]
    fn every_mediated_method_refuses_an_out_of_scope_authority() {
        let all = CapabilityLattice {
            read_files: CapabilityLevel::Always,
            write_files: CapabilityLevel::Always,
            glob_search: CapabilityLevel::Always,
            web_fetch: CapabilityLevel::Always,
            web_search: CapabilityLevel::Always,
            run_bash: CapabilityLevel::Always,
            git_commit: CapabilityLevel::Always,
            git_push: CapabilityLevel::Always,
            spawn_agent: CapabilityLevel::Always,
            ..CapabilityLattice::bottom()
        };
        // `read_auth()` is the wrong scope for every one of these.
        let fx = PolicyEnforced {
            inner: RecordingEffects::new(),
            receipts: Arc::new(crate::receipt::ReceiptLog::new()),
            policy: all,
        };

        let outcomes: Vec<(&str, bool)> = vec![
            (
                "write",
                fx.write(Path::new("/tmp/x"), b"x", read_auth()).is_err(),
            ),
            (
                "append",
                fx.append(Path::new("/tmp/x"), b"x", read_auth()).is_err(),
            ),
            ("glob", fx.glob("*.rs", read_auth()).is_err()),
            (
                "fetch",
                WebEffect::fetch(&fx, "https://example.com", read_auth()).is_err(),
            ),
            ("search", fx.search("q", read_auth()).is_err()),
            ("run", fx.run("ls", read_auth()).is_err()),
            ("commit", fx.commit("msg", read_auth()).is_err()),
            ("push", fx.push("origin", "main", read_auth()).is_err()),
            ("spawn", fx.spawn("http://a", "{}", read_auth()).is_err()),
        ];
        for (name, refused) in &outcomes {
            assert!(refused, "{name} accepted an out-of-scope authority");
        }
        assert!(
            fx.inner.calls().is_empty(),
            "every refusal must precede the effect; inner calls: {:?}",
            fx.inner.calls()
        );
    }

    /// No false denial: each method ACCEPTS the authority earned for it and
    /// reaches the inner effect. Without this, a scope check that refused
    /// everything would satisfy the test above and break the runtime.
    #[test]
    fn every_mediated_method_accepts_its_own_authority() {
        let fx = PolicyEnforced {
            inner: RecordingEffects::new(),
            receipts: Arc::new(crate::receipt::ReceiptLog::new()),
            policy: CapabilityLattice {
                read_files: CapabilityLevel::Always,
                write_files: CapabilityLevel::Always,
                glob_search: CapabilityLevel::Always,
                web_fetch: CapabilityLevel::Always,
                web_search: CapabilityLevel::Always,
                run_bash: CapabilityLevel::Always,
                git_commit: CapabilityLevel::Always,
                git_push: CapabilityLevel::Always,
                spawn_agent: CapabilityLevel::Always,
                ..CapabilityLattice::bottom()
            },
        };

        fx.read(Path::new("/tmp/x"), read_auth()).expect("read");
        fx.write(Path::new("/tmp/x"), b"x", write_auth())
            .expect("write");
        fx.append(Path::new("/tmp/x"), b"x", write_auth())
            .expect("append");
        fx.glob("*.rs", glob_auth()).expect("glob");
        WebEffect::fetch(&fx, "https://example.com", fetch_auth()).expect("fetch");
        fx.search("q", search_auth()).expect("search");
        fx.run("ls", shell_auth()).expect("run");
        fx.commit("msg", commit_auth()).expect("commit");
        fx.push("origin", "main", push_auth()).expect("push");
        fx.spawn("http://a", "{}", spawn_auth()).expect("spawn");

        // All ten reached the inner impl — nothing was refused on scope.
        assert_eq!(
            fx.inner.calls().len(),
            10,
            "every correctly-scoped call must reach the effect: {:?}",
            fx.inner.calls()
        );
    }

    // ── Receipts: every mediated decision is witnessed ─────────────────────

    /// Completeness: each mediated call appends exactly one receipt, naming the
    /// `(Operation, SinkClass)` it was decided for, in call order — and the
    /// chain verifies.
    ///
    /// This is the property the receipt exists for. A log that were merely
    /// *present* would prove nothing; what makes it evidence is that the count
    /// matches the number of effects and the contents match what was decided.
    #[test]
    fn every_mediated_call_is_witnessed_exactly_once() {
        use crate::receipt::EffectOutcome;
        use portcullis_core::{Operation as Op, SinkClass as Sink};

        let fx = PolicyEnforced {
            inner: RecordingEffects::new(),
            receipts: Arc::new(crate::receipt::ReceiptLog::new()),
            policy: CapabilityLattice {
                read_files: CapabilityLevel::Always,
                write_files: CapabilityLevel::Always,
                glob_search: CapabilityLevel::Always,
                web_fetch: CapabilityLevel::Always,
                web_search: CapabilityLevel::Always,
                run_bash: CapabilityLevel::Always,
                git_commit: CapabilityLevel::Always,
                git_push: CapabilityLevel::Always,
                spawn_agent: CapabilityLevel::Always,
                ..CapabilityLattice::bottom()
            },
        };

        fx.read(Path::new("/tmp/x"), read_auth()).expect("read");
        fx.write(Path::new("/tmp/x"), b"x", write_auth())
            .expect("write");
        fx.append(Path::new("/tmp/x"), b"x", write_auth())
            .expect("append");
        fx.glob("*.rs", glob_auth()).expect("glob");
        WebEffect::fetch(&fx, "https://example.com", fetch_auth()).expect("fetch");
        fx.search("q", search_auth()).expect("search");
        fx.run("ls", shell_auth()).expect("run");
        fx.commit("msg", commit_auth()).expect("commit");
        fx.push("origin", "main", push_auth()).expect("push");
        fx.spawn("http://a", "{}", spawn_auth()).expect("spawn");

        let entries = fx.receipts().entries();
        assert_eq!(
            entries.len(),
            10,
            "one receipt per mediated call; got {entries:?}"
        );
        // Every receipt proves its own membership against the log root — the
        // check an auditor runs holding one entry and an O(log n) proof, not the
        // whole log.
        let root = fx.receipts().root();
        for (i, e) in entries.iter().enumerate() {
            let proof = fx
                .receipts()
                .inclusion_proof(i as u64)
                .expect("entry is in range");
            assert!(
                crate::receipt::verify_inclusion(
                    &e.leaf_hash(),
                    i as u64,
                    entries.len() as u64,
                    &proof,
                    &root,
                ),
                "receipt {i} could not prove inclusion"
            );
        }

        let expected = [
            (Op::ReadFiles, Sink::AuditLogAppend),
            (Op::WriteFiles, Sink::WorkspaceWrite),
            (Op::WriteFiles, Sink::WorkspaceWrite), // append shares the write sink
            (Op::GlobSearch, Sink::AuditLogAppend),
            (Op::WebFetch, Sink::HTTPEgress),
            (Op::WebSearch, Sink::HTTPEgress),
            (Op::RunBash, Sink::BashExec),
            (Op::GitCommit, Sink::GitCommit),
            (Op::GitPush, Sink::GitPush),
            (Op::SpawnAgent, Sink::AgentSpawn),
        ];
        for (i, (op, sink)) in expected.iter().enumerate() {
            assert_eq!(entries[i].operation, *op, "receipt {i} operation");
            assert_eq!(entries[i].sink_class, *sink, "receipt {i} sink");
            assert_eq!(entries[i].outcome, EffectOutcome::Allowed, "receipt {i}");
        }
    }

    /// The three that the log used to miss: `run_argv`, `run_argv_async` and
    /// `NetEffect::fetch`.
    ///
    /// These do not spend inside `PolicyEnforced` — they forward the authority
    /// and it is consumed in the inner effect — so a receipt written at the gate
    /// could not cover them, and for a while did not. Process execution and
    /// network egress were the two effects absent from the transparency log,
    /// which is close to the only two an exfiltration story needs.
    ///
    /// They are covered now because the receipt is written by `Authority::spend`,
    /// wherever that happens to be. Note what this test would catch that the
    /// count-based test above would not: `witnessed()` not being attached in one
    /// of the three forwarding methods. Enforcement would still be correct — the
    /// spend still happens — and the effect would silently leave no trace.
    #[cfg(all(feature = "net", feature = "async"))]
    #[tokio::test]
    async fn the_deferred_spend_methods_are_witnessed_where_they_spend() {
        use crate::receipt::EffectOutcome;
        use portcullis_core::{Operation as Op, SinkClass as Sink};

        let fx = PolicyEnforced {
            inner: RecordingEffects::new(),
            receipts: Arc::new(crate::receipt::ReceiptLog::new()),
            policy: CapabilityLattice {
                run_bash: CapabilityLevel::Always,
                web_fetch: CapabilityLevel::Always,
                ..CapabilityLattice::bottom()
            },
        };

        let env = BTreeMap::new();
        fx.run_argv("ls", &[], Path::new("/tmp"), None, &env, None, shell_auth())
            .expect("run_argv");

        fx.run_argv_async(
            "ls",
            &[],
            Path::new("/tmp"),
            None,
            &env,
            None,
            None,
            shell_auth(),
        )
        .await
        .expect("run_argv_async");

        NetEffect::fetch(
            &fx,
            &reqwest::Client::new(),
            NetCapability::WebFetch,
            reqwest::Method::GET,
            "https://example.com".parse().expect("url"),
            &[],
            None,
            None,
            fetch_auth(),
        )
        .await
        .expect("net fetch");

        let entries = fx.receipts().entries();
        assert_eq!(
            entries.len(),
            3,
            "each deferred-spend method must leave exactly one receipt; got {entries:?}"
        );
        let got: Vec<_> = entries
            .iter()
            .map(|e| (e.operation, e.sink_class, e.outcome))
            .collect();
        assert_eq!(
            got,
            vec![
                (Op::RunBash, Sink::BashExec, EffectOutcome::Allowed),
                (Op::RunBash, Sink::BashExec, EffectOutcome::Allowed),
                (Op::WebFetch, Sink::HTTPEgress, EffectOutcome::Allowed),
            ],
            "the shell spawns and the egress must each be named in the log"
        );
    }

    /// A refusal is witnessed too, and distinguishes WHY. An audit that recorded
    /// only successes would let a refused push vanish from the record; one that
    /// collapsed the two denial kinds could not tell "capability off" from
    /// "wrong authority presented".
    #[test]
    fn refusals_are_witnessed_and_say_which_check_refused() {
        use crate::receipt::EffectOutcome;

        // `git_push` off entirely → the coarse lattice refuses.
        let denied_by_policy = PolicyEnforced {
            inner: RecordingEffects::new(),
            receipts: Arc::new(crate::receipt::ReceiptLog::new()),
            policy: CapabilityLattice::bottom(),
        };
        let _ = denied_by_policy.push("origin", "main", push_auth());
        assert_eq!(
            denied_by_policy.receipts().entries()[0].outcome,
            EffectOutcome::DeniedByPolicy
        );

        // `git_push` on, but the wrong authority → the scope check refuses.
        let denied_by_scope = PolicyEnforced {
            inner: RecordingEffects::new(),
            receipts: Arc::new(crate::receipt::ReceiptLog::new()),
            policy: CapabilityLattice {
                git_push: CapabilityLevel::Always,
                ..CapabilityLattice::bottom()
            },
        };
        let _ = denied_by_scope.push("origin", "main", commit_auth());
        let e = &denied_by_scope.receipts().entries()[0];
        assert_eq!(e.outcome, EffectOutcome::DeniedByScope);
        assert_eq!(e.operation, portcullis_core::Operation::GitPush);
        assert_eq!(e.sink_class, portcullis_core::SinkClass::GitPush);
    }

    // ── EffectError ────────────────────────────────────────────────────────

    #[test]
    fn effect_error_display() {
        assert_eq!(
            EffectError::PolicyDenied("no access".into()).to_string(),
            "policy denied: no access"
        );
        assert_eq!(
            EffectError::Io("disk full".into()).to_string(),
            "I/O error: disk full"
        );
        assert_eq!(
            EffectError::PathViolation("../escape".into()).to_string(),
            "path violation: ../escape"
        );
        assert_eq!(
            EffectError::CommandFailed {
                exit_code: Some(1),
                stderr: "oops".into()
            }
            .to_string(),
            "command failed (exit=Some(1)): oops"
        );
        assert_eq!(
            EffectError::NotImplemented("web fetch").to_string(),
            "not implemented: web fetch"
        );
    }

    // ── DenyAllEffects ────────────────────────────────────────────────────

    #[test]
    fn deny_all_rejects_every_call() {
        let fx = DenyAllEffects;
        assert!(matches!(
            fx.read(Path::new("file.txt"), read_auth()),
            Err(EffectError::PolicyDenied(_))
        ));
        assert!(matches!(
            fx.write(Path::new("file.txt"), b"data", write_auth()),
            Err(EffectError::PolicyDenied(_))
        ));
        assert!(matches!(
            fx.glob("*.rs", glob_auth()),
            Err(EffectError::PolicyDenied(_))
        ));
        assert!(matches!(
            WebEffect::fetch(&fx, "https://example.com", fetch_auth()),
            Err(EffectError::PolicyDenied(_))
        ));
        assert!(matches!(
            fx.run("ls", shell_auth()),
            Err(EffectError::PolicyDenied(_))
        ));
        assert!(matches!(
            fx.commit("msg", commit_auth()),
            Err(EffectError::PolicyDenied(_))
        ));
        assert!(matches!(
            fx.push("origin", "main", push_auth()),
            Err(EffectError::PolicyDenied(_))
        ));
        assert!(matches!(
            fx.spawn("http://agent", "{}", spawn_auth()),
            Err(EffectError::PolicyDenied(_))
        ));
    }

    // ── RecordingEffects ──────────────────────────────────────────────────

    #[test]
    fn recording_records_calls_in_order() {
        let fx = RecordingEffects::new();
        let _ = fx.read(Path::new("a.rs"), read_auth());
        let _ = fx.write(Path::new("b.rs"), b"hi", write_auth());
        let _ = fx.run("echo hello", shell_auth());
        let calls = fx.calls();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].kind, "read");
        assert_eq!(calls[1].kind, "write");
        assert_eq!(calls[2].kind, "run");
    }

    #[test]
    fn recording_returns_configured_file_content() {
        let fx = RecordingEffects::new().with_file_content(b"hello world".to_vec());
        let bytes = fx.read(Path::new("any.txt"), read_auth()).unwrap();
        assert_eq!(bytes, b"hello world");
    }

    #[test]
    fn recording_commit_returns_stub_hash() {
        let fx = RecordingEffects::new();
        let hash = fx.commit("fix: something", commit_auth()).unwrap();
        assert_eq!(hash, "deadbeef");
    }

    // ── AllowListEffects ──────────────────────────────────────────────────

    #[test]
    fn allow_list_path_prefix_enforcement() {
        let fx = AllowListEffects::new().allow_path("/workspace/src");
        assert!(fx
            .read(Path::new("/workspace/src/main.rs"), read_auth())
            .is_ok());
        assert!(matches!(
            fx.read(Path::new("/etc/passwd"), read_auth()),
            Err(EffectError::PathViolation(_))
        ));
        assert!(matches!(
            fx.read(Path::new("/workspace/secrets"), read_auth()),
            Err(EffectError::PathViolation(_))
        ));
    }

    #[test]
    fn allow_list_url_prefix_enforcement() {
        let fx = AllowListEffects::new().allow_url("https://docs.rs/");
        assert!(fx.fetch("https://docs.rs/portcullis", fetch_auth()).is_ok());
        assert!(matches!(
            fx.fetch("https://evil.com/exfil", fetch_auth()),
            Err(EffectError::PolicyDenied(_))
        ));
    }

    // ── PolicyEnforced — policy gate ──────────────────────────────────────

    #[test]
    fn policy_enforced_denies_when_capability_is_never() {
        let policy = CapabilityLattice::bottom();
        let fx = PolicyEnforced {
            inner: RecordingEffects::new(),
            receipts: Arc::new(crate::receipt::ReceiptLog::new()),
            policy,
        };
        assert!(matches!(
            fx.read(Path::new("file.txt"), read_auth()),
            Err(EffectError::PolicyDenied(_))
        ));
        assert!(matches!(
            WebEffect::fetch(&fx, "https://example.com", fetch_auth()),
            Err(EffectError::PolicyDenied(_))
        ));
        assert!(matches!(
            fx.run("ls", shell_auth()),
            Err(EffectError::PolicyDenied(_))
        ));
        assert!(matches!(
            fx.commit("msg", commit_auth()),
            Err(EffectError::PolicyDenied(_))
        ));
        assert!(matches!(
            fx.push("origin", "main", push_auth()),
            Err(EffectError::PolicyDenied(_))
        ));
        // Nothing should have reached the inner impl
        let recording = &fx.inner;
        assert!(recording.calls().is_empty());
    }

    #[test]
    fn policy_enforced_allows_when_capability_is_sufficient() {
        let mut policy = CapabilityLattice::bottom();
        policy.read_files = CapabilityLevel::Always;
        policy.glob_search = CapabilityLevel::LowRisk;

        let fx = PolicyEnforced {
            inner: RecordingEffects::new(),
            receipts: Arc::new(crate::receipt::ReceiptLog::new()),
            policy,
        };
        // These should reach the inner impl
        assert!(fx.read(Path::new("file.txt"), read_auth()).is_ok());
        assert!(fx.glob("*.rs", glob_auth()).is_ok());
        assert_eq!(fx.inner.calls().len(), 2);
        // But web_fetch is still Never
        assert!(matches!(
            WebEffect::fetch(&fx, "https://example.com", fetch_auth()),
            Err(EffectError::PolicyDenied(_))
        ));
    }

    #[test]
    fn production_effects_requires_policy() {
        let policy = CapabilityLattice::bottom();
        let fx = production_effects(policy);
        // Everything denied — confirming production_effects wraps in PolicyEnforced
        assert!(matches!(
            fx.read(Path::new("any.txt"), read_auth()),
            Err(EffectError::PolicyDenied(_))
        ));
    }

    #[test]
    fn production_effects_allows_read_when_policy_permits() {
        let mut policy = CapabilityLattice::bottom();
        policy.read_files = CapabilityLevel::Always;

        let fx = production_effects(policy);
        // Should pass the policy gate — will fail at I/O level (file missing)
        let result = fx.read(Path::new("/nonexistent/path/to/missing.txt"), read_auth());
        assert!(matches!(result, Err(EffectError::Io(_))));
    }

    // ── RealEffects is unconstructible by callers ─────────────────────────

    // Compile-time test: the following would not compile because RealEffects is pub(crate):
    // let _ = RealEffects::new();  // ERROR: function `new` is private / type is pub(crate)

    #[test]
    fn real_effects_web_fetch_returns_not_implemented() {
        // Reach RealEffects through the production constructor with web allowed
        let mut policy = CapabilityLattice::bottom();
        policy.web_fetch = CapabilityLevel::Always;
        let fx = production_effects(policy);
        assert!(matches!(
            WebEffect::fetch(&fx, "https://example.com", fetch_auth()),
            Err(EffectError::NotImplemented(_))
        ));
    }

    // ── glob helpers ──────────────────────────────────────────────────────

    #[test]
    fn glob_to_regex_converts_star_star() {
        let re = glob_to_regex("src/**/*.rs");
        let r = regex::Regex::new(&re).unwrap();
        assert!(r.is_match("src/foo/bar/baz.rs"));
        assert!(!r.is_match("src/foo/bar/baz.txt"));
    }

    #[test]
    fn glob_to_regex_single_star_does_not_cross_slash() {
        let re = glob_to_regex("src/*.rs");
        let r = regex::Regex::new(&re).unwrap();
        assert!(r.is_match("src/main.rs"));
        assert!(!r.is_match("src/foo/bar.rs"));
    }

    #[test]
    fn glob_to_regex_escapes_dots() {
        let re = glob_to_regex("file.txt");
        let r = regex::Regex::new(&re).unwrap();
        assert!(r.is_match("file.txt"));
        assert!(!r.is_match("fileXtxt"));
    }

    // ── ShellOutput helpers ───────────────────────────────────────────────

    #[test]
    fn shell_output_success() {
        let out = ShellOutput {
            stdout: b"hello\n".to_vec(),
            stderr: Vec::new(),
            exit_code: 0,
        };
        assert!(out.success());
        assert_eq!(out.stdout_str(), "hello\n");
    }

    #[test]
    fn shell_output_failure() {
        let out = ShellOutput {
            stdout: Vec::new(),
            stderr: b"error\n".to_vec(),
            exit_code: 1,
        };
        assert!(!out.success());
        assert_eq!(out.stderr_str(), "error\n");
    }

    // ── Real file I/O through PolicyEnforced ──────────────────────────────

    #[test]
    fn real_file_roundtrip_through_policy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.txt");

        let mut policy = CapabilityLattice::bottom();
        policy.read_files = CapabilityLevel::Always;
        policy.write_files = CapabilityLevel::Always;

        let fx = production_effects(policy);
        fx.write(&path, b"hello effects", write_auth()).unwrap();
        let bytes = fx.read(&path, read_auth()).unwrap();
        assert_eq!(bytes, b"hello effects");
    }

    #[test]
    fn real_shell_runs_through_policy() {
        let mut policy = CapabilityLattice::bottom();
        policy.run_bash = CapabilityLevel::Always;
        let fx = production_effects(policy);
        let out = fx.run("echo nucleus", shell_auth()).unwrap();
        assert!(out.success());
        assert!(out.stdout_str().contains("nucleus"));
    }

    // ── Structured argv spawn (run_argv) — the sealed home (B1) ───────────
    //
    // Mirrors the nucleus `Executor` spawn behavior tests: a real command runs
    // from an argv, its output is captured, `cwd` is honored, and the child
    // environment is isolated (env_clear + only the allowlist). Requires a
    // real `DischargedBundle` (minted by `preflight_action` via the sealed test
    // helper) — the structured spawn only proceeds past a discharged bundle.
    #[cfg(unix)]
    #[test]
    fn real_run_argv_captures_output_cwd_and_env_isolation() {
        // A shell spawn needs a SHELL-scoped bundle. This test used
        // `allowed_bundle()` — a WriteFiles/WorkspaceWrite bundle — to authorise
        // `run_argv`, which is the confused deputy sitting in the test suite:
        // authority earned for one action presented for another. It passed only
        // because the bundle was an unused `_proof` token.
        use portcullis_core::discharge::test_helpers::bundle_for;
        use portcullis_core::{Operation, SinkClass};

        let mut policy = CapabilityLattice::bottom();
        policy.run_bash = CapabilityLevel::Always;
        let fx = production_effects(policy);
        // One authority per spawn: an `Authority` is spent by the call, so a
        // single bundle can no longer cover four of them. That is the property,
        // not an inconvenience — this test used to replay one discharge.
        let shell_authority =
            || Authority::new(bundle_for(Operation::RunBash, SinkClass::BashExec));

        let dir = tempfile::tempdir().unwrap();
        let want_cwd = dir.path().canonicalize().unwrap();

        let mut allowed_env = BTreeMap::new();
        allowed_env.insert("ALLOWED_TOKEN".to_string(), "argv-value-123".to_string());

        // (1) `pwd` proves `current_dir` was honored. The program name is
        //     resolved via the parent PATH even though the child env is cleared.
        let pwd_out = fx
            .run_argv(
                "pwd",
                &[],
                dir.path(),
                None,
                &allowed_env,
                None,
                shell_authority(),
            )
            .expect("run_argv spawns pwd");
        assert!(pwd_out.status.success());
        let printed_cwd = String::from_utf8_lossy(&pwd_out.stdout);
        assert_eq!(
            Path::new(printed_cwd.trim()).canonicalize().unwrap(),
            want_cwd,
            "run_argv must honor cwd",
        );

        // (2) `printenv` proves the env allowlist passed through AND that parent
        //     variables were cleared (PATH is set in the test parent; it must
        //     not appear in the child's environment after env_clear).
        let env_out = fx
            .run_argv(
                "printenv",
                &[],
                dir.path(),
                None,
                &allowed_env,
                None,
                shell_authority(),
            )
            .expect("run_argv spawns printenv");
        assert!(env_out.status.success());
        let printed_env = String::from_utf8_lossy(&env_out.stdout);
        assert!(
            printed_env.contains("ALLOWED_TOKEN=argv-value-123"),
            "allowlisted env var must reach the child: {printed_env:?}",
        );
        assert!(
            !printed_env.lines().any(|l| l.starts_with("PATH=")),
            "parent PATH must not leak into the child (env isolation): {printed_env:?}",
        );

        // (3) stdin plumbing: bytes fed on stdin are delivered to the child.
        let cat_out = fx
            .run_argv(
                "cat",
                &[],
                dir.path(),
                Some(b"piped-stdin"),
                &allowed_env,
                None,
                shell_authority(),
            )
            .expect("run_argv spawns cat with stdin");
        assert!(cat_out.status.success());
        assert_eq!(&cat_out.stdout, b"piped-stdin");
    }

    #[test]
    fn run_argv_denied_when_policy_never() {
        use portcullis_core::discharge::test_helpers::allowed_bundle;

        // run_bash is Never in bottom() — the sealed policy gate must reject the
        // structured spawn just as it rejects `run`.
        let fx = production_effects(CapabilityLattice::bottom());
        let err = fx
            .run_argv(
                "echo",
                &["hi".to_string()],
                Path::new("."),
                None,
                &BTreeMap::new(),
                None,
                Authority::new(allowed_bundle()),
            )
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    // ── Sealed net egress (NetEffect::fetch) — the sealed home (B5) ───────
    //
    // The PolicyEnforced gate must reject the egress when the governing net
    // capability is `Never` in policy, BEFORE any network send occurs — the
    // net analogue of `run_argv_denied_when_policy_never`. `bottom()` has both
    // `web_fetch` and `web_search` == Never, so both discriminants short-circuit
    // to `PolicyDenied` without touching the wire (no runtime I/O in this test).
    /// `require_scope` refuses a bundle earned for a different action.
    ///
    /// The wiring at each effect is a one-liner mirroring the shell spawn, whose
    /// rejection is bite-verified end to end. This covers the decision itself
    /// for every operation currently enforced, including the paths a unit test
    /// cannot reach: `NetEffect::fetch` on `RealEffects` sits behind the policy
    /// wrapper, which short-circuits before delegating, so exercising it would
    /// need a permissive policy and a live request.
    ///
    /// arXiv 2606.28679, "Capability Gates Are Not Authorization", names this
    /// exact failure: holding a capability is not the same as being authorised
    /// for the action at hand, and an unbound token is how an adversary steers
    /// an agent's egress at a target the principal never approved.
    #[test]
    fn require_scope_refuses_a_bundle_earned_for_another_action() {
        use portcullis_core::discharge::test_helpers::bundle_for;
        use portcullis_core::{Operation, SinkClass};

        let shell = bundle_for(Operation::RunBash, SinkClass::BashExec);
        let egress = bundle_for(Operation::WebFetch, SinkClass::HTTPEgress);

        // Each bundle authorises its own action.
        assert!(require_scope(&shell, Operation::RunBash, SinkClass::BashExec).is_ok());
        assert!(require_scope(&egress, Operation::WebFetch, SinkClass::HTTPEgress).is_ok());

        // Neither authorises the other's — the confused deputy, refused.
        let err = require_scope(&shell, Operation::WebFetch, SinkClass::HTTPEgress)
            .expect_err("a shell bundle must not authorise http egress");
        assert!(err.contains("scope mismatch"), "unexpected error: {err}");

        let err = require_scope(&egress, Operation::RunBash, SinkClass::BashExec)
            .expect_err("an egress bundle must not authorise a shell spawn");
        assert!(err.contains("scope mismatch"), "unexpected error: {err}");
    }

    #[cfg(feature = "net")]
    #[tokio::test]
    async fn net_fetch_denied_when_policy_never() {
        use portcullis_core::discharge::test_helpers::allowed_bundle;

        // The workspace reqwest uses `rustls-no-provider`; install a provider so
        // `Client::new()` can build (idempotent — ignore the already-set Err).
        let _ = rustls::crypto::ring::default_provider().install_default();
        let fx = production_effects_concrete(CapabilityLattice::bottom());
        let client = reqwest::Client::new();
        let url: reqwest::Url = "https://example.com/".parse().unwrap();

        for cap in [NetCapability::WebFetch, NetCapability::WebSearch] {
            // Disambiguate: `PolicyEnforced` also impls `WebEffect::fetch(&str)`.
            let err = NetEffect::fetch(
                &fx,
                &client,
                cap,
                reqwest::Method::GET,
                url.clone(),
                &[],
                None,
                None,
                Authority::new(allowed_bundle()),
            )
            .await
            .expect_err("Never-policy egress must be denied before any send");
            assert!(
                matches!(err, EffectError::PolicyDenied(_)),
                "{cap:?} egress under a Never policy must be PolicyDenied, got {err:?}"
            );
        }
    }
}

#[cfg(test)]
mod witness_completeness_tests {
    /// **The invariant `witnessed`'s own docs state as prose, enforced.**
    ///
    /// Those docs say: *"Every method that accepts an `Authority` routes it
    /// through here — the ten via `gate`, the three that spend further down by
    /// calling this directly."* That is a completeness claim about a set of
    /// methods, and nothing checked it. A method added later that spends without
    /// routing through `witnessed` would leave its effect unrecorded, and every
    /// existing test would stay green — which is exactly the shape of the
    /// original gap this work started from: the three most dangerous effects
    /// (`run_argv`, `run_argv_async`, `NetEffect::fetch`) were outside the log
    /// while every safer one was inside it.
    ///
    /// A source scan rather than a behavioural test, deliberately: the property
    /// is about EVERY method including ones not yet written, and a behavioural
    /// test only covers the paths it happens to exercise.
    #[test]
    fn every_policy_enforced_method_routes_its_authority_through_the_witness() {
        let src = include_str!("lib.rs");
        let body = src
            .split("#[cfg(test)]")
            .next()
            .expect("source before the tests");

        // Only `impl ... for PolicyEnforced` blocks: the mediation layer is
        // where the routing obligation lives. Trait DECLARATIONS and the inert
        // `Deny*`/test doubles take an authority and correctly drop it.
        let mut offenders = Vec::new();
        let mut checked = 0usize;
        for block in body.split("impl").skip(1) {
            let header: String = block.lines().next().unwrap_or("").to_string();
            // Any impl ON PolicyEnforced, inherent or trait. An earlier version
            // matched only `for PolicyEnforced` and so skipped inherent impls
            // entirely — which is where `gate` and `witnessed` themselves live,
            // and where a helper that spent without routing would most naturally
            // be added.
            if !header.contains("PolicyEnforced") {
                continue;
            }
            // Cut the block at the next top-level `impl` — `split` already did.
            for chunk in block.split("    fn ").skip(1) {
                let sig = chunk.lines().take(6).collect::<Vec<_>>().join(" ");
                if !sig.contains("authority: Authority") {
                    continue;
                }
                checked += 1;
                let name = chunk.split('(').next().unwrap_or("<unknown>").trim();
                // `witnessed_by` counts: it is what `witnessed` itself calls, so
                // the helper that attaches the log must not be flagged for
                // attaching the log.
                if !chunk.contains(".gate(")
                    && !chunk.contains(".witnessed(")
                    && !chunk.contains(".witnessed_by(")
                {
                    offenders.push(name.to_string());
                }
            }
        }

        // Non-vacuity FIRST. A scan that matched nothing would pass forever and
        // look identical to a clean result — the failure mode that let the
        // original gap sit unnoticed. Checked before the real assertion so a
        // broken scan reports as a broken scan rather than as success.
        assert!(
            checked >= 10,
            "the scan found only {checked} PolicyEnforced methods taking an authority; \
             the docs claim thirteen, so a scan finding fewer is broken, not clean"
        );

        assert!(
            offenders.is_empty(),
            "these PolicyEnforced methods take an `Authority` without routing it \
             through `gate`/`witnessed`, so the effects they authorise leave no \
             receipt:\n  {}",
            offenders.join("\n  ")
        );
    }
}
