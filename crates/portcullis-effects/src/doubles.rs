//! Effect doubles — the implementations that record, deny or simulate.
//!
//! Carved out of `lib.rs` when binding the authority to its target pushed that
//! file past its line ratchet. The split follows a real seam rather than a
//! convenient line: nothing here performs real I/O, which is exactly the
//! distinction `scripts/inert-authority-manifest.txt` draws when it classes
//! these scopes `N` and judges `RealEffects` by what it actually does.
//!
//! `RecordingEffects` is the one that is not purely inert. Its
//! `run`/`commit`/`push`/`run_argv` and its `NetEffect::fetch` **spend** the
//! authority they are handed, because `PolicyEnforced` forwards those without
//! spending and the consumption has to happen somewhere. A double that dropped
//! the authority where the real one spends would diverge from it on exactly the
//! property the receipt tests check.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};

use crate::authority::Authority;
use crate::{
    AgentSpawnEffect, EffectError, FileEffect, GitEffect, SearchResult, ShellEffect, ShellOutput,
    WebEffect, act_commit, act_push, act_run,
};

// `NetEffect` is implemented here only under `cfg(test)` — building a
// `reqwest::Response` from nothing needs `http`, which is a dev-dependency —
// so the import is gated the same way.
#[cfg(test)]
use crate::{NetCapability, NetEffect};

#[cfg(feature = "async")]
use crate::AsyncShellSpawnEffect;

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
/// # use portcullis_core::discharge::test_helpers::{bundle_for, bundle_for_subject};
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
    fn run(&self, cmd: &str, authority: Authority) -> Result<ShellOutput, EffectError> {
        // Spent, for the reason `RecordingEffects::run_argv` spends: these are
        // methods `PolicyEnforced` now forwards without spending, so the
        // consumption happens here. A double that dropped the authority would
        // silently diverge from the real implementation on the exact property
        // the receipt tests check — and did, for one commit: the scope check
        // vanished entirely and `a_commit_authority_will_not_pay_for_a_push`
        // caught it.
        drop(
            authority
                .spend_on(&act_run(cmd))
                .map_err(|e| EffectError::PolicyDenied(e.to_string()))?,
        );
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
    fn commit(&self, message: &str, authority: Authority) -> Result<String, EffectError> {
        // Spent, for the reason `RecordingEffects::run_argv` spends: these are
        // methods `PolicyEnforced` now forwards without spending, so the
        // consumption happens here. A double that dropped the authority would
        // silently diverge from the real implementation on the exact property
        // the receipt tests check — and did, for one commit: the scope check
        // vanished entirely and `a_commit_authority_will_not_pay_for_a_push`
        // caught it.
        drop(
            authority
                .spend_on(&act_commit(message))
                .map_err(|e| EffectError::PolicyDenied(e.to_string()))?,
        );
        self.record("commit", message);
        Ok("deadbeef".to_string())
    }

    fn push(&self, remote: &str, branch: &str, authority: Authority) -> Result<(), EffectError> {
        // Spent, for the reason `RecordingEffects::run_argv` spends: these are
        // methods `PolicyEnforced` now forwards without spending, so the
        // consumption happens here. A double that dropped the authority would
        // silently diverge from the real implementation on the exact property
        // the receipt tests check — and did, for one commit: the scope check
        // vanished entirely and `a_commit_authority_will_not_pay_for_a_push`
        // caught it.
        drop(
            authority
                .spend_on(&act_push(remote))
                .map_err(|e| EffectError::PolicyDenied(e.to_string()))?,
        );
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
/// # use portcullis_core::discharge::test_helpers::{bundle_for, bundle_for_subject};
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
/// # use portcullis_core::discharge::test_helpers::{bundle_for, bundle_for_subject};
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
