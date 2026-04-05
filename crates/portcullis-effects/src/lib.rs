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
//! // Policy is checked here — no need to call preflight separately
//! let contents = fx.read(Path::new("src/main.rs"))?;
//! fx.fetch("https://example.com")?;
//! ```
//!
//! ## Testing
//!
//! ```rust
//! use portcullis_effects::{DenyAllEffects, RecordingEffects, FileEffect};
//!
//! // DenyAllEffects rejects everything — useful for testing deny paths
//! let fx = DenyAllEffects;
//! assert!(fx.read(std::path::Path::new("file.txt")).is_err());
//!
//! // RecordingEffects records all calls — useful for asserting what was invoked
//! let fx = RecordingEffects::new();
//! let _ = fx.read(std::path::Path::new("file.txt"));
//! assert_eq!(fx.calls().len(), 1);
//! ```

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

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
pub trait FileEffect {
    /// Read the full contents of a file.
    fn read(&self, path: &Path) -> Result<Vec<u8>, EffectError>;

    /// Write bytes to a file, creating it if it does not exist.
    fn write(&self, path: &Path, content: &[u8]) -> Result<(), EffectError>;

    /// Append bytes to a file, creating it if it does not exist.
    fn append(&self, path: &Path, content: &[u8]) -> Result<(), EffectError>;

    /// List files matching a glob pattern. Returns absolute paths.
    fn glob(&self, pattern: &str) -> Result<Vec<PathBuf>, EffectError>;

    /// Read the full contents of a file as UTF-8.
    fn read_str(&self, path: &Path) -> Result<String, EffectError> {
        let bytes = self.read(path)?;
        String::from_utf8(bytes).map_err(|e| EffectError::Io(format!("UTF-8 decode failed: {e}")))
    }
}

/// Web fetch and search operations.
pub trait WebEffect {
    /// Fetch the body of a URL. Returns raw bytes.
    fn fetch(&self, url: &str) -> Result<Vec<u8>, EffectError>;

    /// Perform a web search and return result snippets.
    fn search(&self, query: &str) -> Result<Vec<SearchResult>, EffectError>;
}

/// Shell command execution.
pub trait ShellEffect {
    /// Run a shell command and return stdout/stderr.
    ///
    /// `cmd` is parsed via `shell-words` to prevent injection.
    fn run(&self, cmd: &str) -> Result<ShellOutput, EffectError>;
}

/// Git operations.
pub trait GitEffect {
    /// Create a git commit with the given message.
    fn commit(&self, message: &str) -> Result<String, EffectError>;

    /// Push the current branch to a remote.
    fn push(&self, remote: &str, branch: &str) -> Result<(), EffectError>;
}

/// Sub-agent spawn operations.
pub trait AgentSpawnEffect {
    /// Spawn a sub-agent at the given endpoint with the given term.
    /// Returns an opaque decision token.
    fn spawn(&self, endpoint: &str, term_json: &str) -> Result<String, EffectError>;
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
/// The only way to obtain a `RealEffects` is through [`production_effects`],
/// which wraps it in `PolicyEnforced` and requires a policy at construction time.
pub(crate) struct RealEffects {
    _private: (),
}

impl RealEffects {
    pub(crate) fn new() -> Self {
        Self { _private: () }
    }
}

impl FileEffect for RealEffects {
    fn read(&self, path: &Path) -> Result<Vec<u8>, EffectError> {
        std::fs::read(path).map_err(|e| EffectError::Io(format!("{}: {e}", path.display())))
    }

    fn write(&self, path: &Path, content: &[u8]) -> Result<(), EffectError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| EffectError::Io(format!("{}: {e}", parent.display())))?;
        }
        std::fs::write(path, content)
            .map_err(|e| EffectError::Io(format!("{}: {e}", path.display())))
    }

    fn append(&self, path: &Path, content: &[u8]) -> Result<(), EffectError> {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| EffectError::Io(format!("{}: {e}", path.display())))?;
        f.write_all(content)
            .map_err(|e| EffectError::Io(format!("{}: {e}", path.display())))
    }

    fn glob(&self, pattern: &str) -> Result<Vec<PathBuf>, EffectError> {
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
    fn fetch(&self, _url: &str) -> Result<Vec<u8>, EffectError> {
        // Synchronous HTTP is intentionally not implemented in portcullis-effects
        // to avoid pulling in a heavyweight HTTP client dependency. Callers that
        // need HTTP should use the nucleus-tool-proxy or inject a custom impl.
        Err(EffectError::NotImplemented(
            "web fetch requires nucleus-tool-proxy; inject a custom WebEffect impl",
        ))
    }

    fn search(&self, _query: &str) -> Result<Vec<SearchResult>, EffectError> {
        Err(EffectError::NotImplemented(
            "web search requires nucleus-tool-proxy; inject a custom WebEffect impl",
        ))
    }
}

impl ShellEffect for RealEffects {
    fn run(&self, cmd: &str) -> Result<ShellOutput, EffectError> {
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
}

impl GitEffect for RealEffects {
    fn commit(&self, message: &str) -> Result<String, EffectError> {
        // Stage all tracked modifications and commit.
        let add = std::process::Command::new("git")
            .args(["add", "-u"])
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

    fn push(&self, remote: &str, branch: &str) -> Result<(), EffectError> {
        let output = std::process::Command::new("git")
            .args(["push", remote, branch])
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
    fn spawn(&self, _endpoint: &str, _term_json: &str) -> Result<String, EffectError> {
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
}

impl<E> PolicyEnforced<E> {
    /// Expose the underlying policy for inspection.
    pub fn policy(&self) -> &CapabilityLattice {
        &self.policy
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
    fn read(&self, path: &Path) -> Result<Vec<u8>, EffectError> {
        self.require(self.policy.read_files, "read_files")?;
        self.inner.read(path)
    }

    fn write(&self, path: &Path, content: &[u8]) -> Result<(), EffectError> {
        self.require(self.policy.write_files, "write_files")?;
        self.inner.write(path, content)
    }

    fn append(&self, path: &Path, content: &[u8]) -> Result<(), EffectError> {
        self.require(self.policy.write_files, "write_files (append)")?;
        self.inner.append(path, content)
    }

    fn glob(&self, pattern: &str) -> Result<Vec<PathBuf>, EffectError> {
        self.require(self.policy.glob_search, "glob_search")?;
        self.inner.glob(pattern)
    }
}

impl<E: WebEffect> WebEffect for PolicyEnforced<E> {
    fn fetch(&self, url: &str) -> Result<Vec<u8>, EffectError> {
        self.require(self.policy.web_fetch, "web_fetch")?;
        self.inner.fetch(url)
    }

    fn search(&self, query: &str) -> Result<Vec<SearchResult>, EffectError> {
        self.require(self.policy.web_search, "web_search")?;
        self.inner.search(query)
    }
}

impl<E: ShellEffect> ShellEffect for PolicyEnforced<E> {
    fn run(&self, cmd: &str) -> Result<ShellOutput, EffectError> {
        self.require(self.policy.run_bash, "run_bash")?;
        self.inner.run(cmd)
    }
}

impl<E: GitEffect> GitEffect for PolicyEnforced<E> {
    fn commit(&self, message: &str) -> Result<String, EffectError> {
        self.require(self.policy.git_commit, "git_commit")?;
        self.inner.commit(message)
    }

    fn push(&self, remote: &str, branch: &str) -> Result<(), EffectError> {
        self.require(self.policy.git_push, "git_push")?;
        self.inner.push(remote, branch)
    }
}

impl<E: AgentSpawnEffect> AgentSpawnEffect for PolicyEnforced<E> {
    fn spawn(&self, endpoint: &str, term_json: &str) -> Result<String, EffectError> {
        self.require(self.policy.spawn_agent, "spawn_agent")?;
        self.inner.spawn(endpoint, term_json)
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
/// use portcullis_core::{CapabilityLattice, CapabilityLevel};
///
/// let policy = CapabilityLattice {
///     read_files: CapabilityLevel::Always,
///     ..CapabilityLattice::bottom()
/// };
/// let fx = production_effects(policy);
/// // fx implements FileEffect, WebEffect, ShellEffect, GitEffect, AgentSpawnEffect
/// // Policy is checked at every call — no separate preflight needed.
/// let result = fx.read(std::path::Path::new("Cargo.toml"));
/// // May succeed or fail depending on filesystem; policy gate is open.
/// let _ = result;
/// ```
pub fn production_effects(
    policy: CapabilityLattice,
) -> impl FileEffect + WebEffect + ShellEffect + GitEffect + AgentSpawnEffect {
    PolicyEnforced {
        inner: RealEffects::new(),
        policy,
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
///
/// let fx = RecordingEffects::new();
/// let _ = fx.read(std::path::Path::new("src/main.rs"));
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
    fn read(&self, path: &Path) -> Result<Vec<u8>, EffectError> {
        self.record("read", path.display().to_string());
        Ok(self.file_read_response.clone())
    }

    fn write(&self, path: &Path, content: &[u8]) -> Result<(), EffectError> {
        self.record(
            "write",
            format!("{}({} bytes)", path.display(), content.len()),
        );
        Ok(())
    }

    fn append(&self, path: &Path, content: &[u8]) -> Result<(), EffectError> {
        self.record(
            "append",
            format!("{}(+{} bytes)", path.display(), content.len()),
        );
        Ok(())
    }

    fn glob(&self, pattern: &str) -> Result<Vec<PathBuf>, EffectError> {
        self.record("glob", pattern);
        Ok(Vec::new())
    }
}

impl WebEffect for RecordingEffects {
    fn fetch(&self, url: &str) -> Result<Vec<u8>, EffectError> {
        self.record("fetch", url);
        Ok(Vec::new())
    }

    fn search(&self, query: &str) -> Result<Vec<SearchResult>, EffectError> {
        self.record("search", query);
        Ok(Vec::new())
    }
}

impl ShellEffect for RecordingEffects {
    fn run(&self, cmd: &str) -> Result<ShellOutput, EffectError> {
        self.record("run", cmd);
        Ok(ShellOutput {
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit_code: 0,
        })
    }
}

impl GitEffect for RecordingEffects {
    fn commit(&self, message: &str) -> Result<String, EffectError> {
        self.record("commit", message);
        Ok("deadbeef".to_string())
    }

    fn push(&self, remote: &str, branch: &str) -> Result<(), EffectError> {
        self.record("push", format!("{remote}/{branch}"));
        Ok(())
    }
}

impl AgentSpawnEffect for RecordingEffects {
    fn spawn(&self, endpoint: &str, term_json: &str) -> Result<String, EffectError> {
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
///
/// let fx = DenyAllEffects;
/// assert!(fx.read(std::path::Path::new("any.txt")).is_err());
/// ```
pub struct DenyAllEffects;

impl FileEffect for DenyAllEffects {
    fn read(&self, path: &Path) -> Result<Vec<u8>, EffectError> {
        Err(EffectError::PolicyDenied(format!(
            "read denied: {}",
            path.display()
        )))
    }
    fn write(&self, path: &Path, _content: &[u8]) -> Result<(), EffectError> {
        Err(EffectError::PolicyDenied(format!(
            "write denied: {}",
            path.display()
        )))
    }
    fn append(&self, path: &Path, _content: &[u8]) -> Result<(), EffectError> {
        Err(EffectError::PolicyDenied(format!(
            "append denied: {}",
            path.display()
        )))
    }
    fn glob(&self, pattern: &str) -> Result<Vec<PathBuf>, EffectError> {
        Err(EffectError::PolicyDenied(format!("glob denied: {pattern}")))
    }
}

impl WebEffect for DenyAllEffects {
    fn fetch(&self, url: &str) -> Result<Vec<u8>, EffectError> {
        Err(EffectError::PolicyDenied(format!("fetch denied: {url}")))
    }
    fn search(&self, query: &str) -> Result<Vec<SearchResult>, EffectError> {
        Err(EffectError::PolicyDenied(format!("search denied: {query}")))
    }
}

impl ShellEffect for DenyAllEffects {
    fn run(&self, cmd: &str) -> Result<ShellOutput, EffectError> {
        Err(EffectError::PolicyDenied(format!("shell denied: {cmd}")))
    }
}

impl GitEffect for DenyAllEffects {
    fn commit(&self, message: &str) -> Result<String, EffectError> {
        Err(EffectError::PolicyDenied(format!(
            "git commit denied: {message}"
        )))
    }
    fn push(&self, remote: &str, branch: &str) -> Result<(), EffectError> {
        Err(EffectError::PolicyDenied(format!(
            "git push denied: {remote}/{branch}"
        )))
    }
}

impl AgentSpawnEffect for DenyAllEffects {
    fn spawn(&self, endpoint: &str, _term_json: &str) -> Result<String, EffectError> {
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
///
/// let fx = AllowListEffects::new()
///     .allow_path("/workspace/src");
/// assert!(fx.read(std::path::Path::new("/workspace/src/main.rs")).is_ok());
/// assert!(fx.read(std::path::Path::new("/etc/passwd")).is_err());
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
    fn read(&self, path: &Path) -> Result<Vec<u8>, EffectError> {
        self.check_path(path)?;
        Ok(self.file_read_response.clone())
    }

    fn write(&self, path: &Path, _content: &[u8]) -> Result<(), EffectError> {
        self.check_path(path)
    }

    fn append(&self, path: &Path, _content: &[u8]) -> Result<(), EffectError> {
        self.check_path(path)
    }

    fn glob(&self, _pattern: &str) -> Result<Vec<PathBuf>, EffectError> {
        Ok(Vec::new())
    }
}

impl WebEffect for AllowListEffects {
    fn fetch(&self, url: &str) -> Result<Vec<u8>, EffectError> {
        self.check_url(url)?;
        Ok(Vec::new())
    }

    fn search(&self, _query: &str) -> Result<Vec<SearchResult>, EffectError> {
        Ok(Vec::new())
    }
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
            fx.read(Path::new("file.txt")),
            Err(EffectError::PolicyDenied(_))
        ));
        assert!(matches!(
            fx.write(Path::new("file.txt"), b"data"),
            Err(EffectError::PolicyDenied(_))
        ));
        assert!(matches!(fx.glob("*.rs"), Err(EffectError::PolicyDenied(_))));
        assert!(matches!(
            fx.fetch("https://example.com"),
            Err(EffectError::PolicyDenied(_))
        ));
        assert!(matches!(fx.run("ls"), Err(EffectError::PolicyDenied(_))));
        assert!(matches!(
            fx.commit("msg"),
            Err(EffectError::PolicyDenied(_))
        ));
        assert!(matches!(
            fx.push("origin", "main"),
            Err(EffectError::PolicyDenied(_))
        ));
        assert!(matches!(
            fx.spawn("http://agent", "{}"),
            Err(EffectError::PolicyDenied(_))
        ));
    }

    // ── RecordingEffects ──────────────────────────────────────────────────

    #[test]
    fn recording_records_calls_in_order() {
        let fx = RecordingEffects::new();
        let _ = fx.read(Path::new("a.rs"));
        let _ = fx.write(Path::new("b.rs"), b"hi");
        let _ = fx.run("echo hello");
        let calls = fx.calls();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].kind, "read");
        assert_eq!(calls[1].kind, "write");
        assert_eq!(calls[2].kind, "run");
    }

    #[test]
    fn recording_returns_configured_file_content() {
        let fx = RecordingEffects::new().with_file_content(b"hello world".to_vec());
        let bytes = fx.read(Path::new("any.txt")).unwrap();
        assert_eq!(bytes, b"hello world");
    }

    #[test]
    fn recording_commit_returns_stub_hash() {
        let fx = RecordingEffects::new();
        let hash = fx.commit("fix: something").unwrap();
        assert_eq!(hash, "deadbeef");
    }

    // ── AllowListEffects ──────────────────────────────────────────────────

    #[test]
    fn allow_list_path_prefix_enforcement() {
        let fx = AllowListEffects::new().allow_path("/workspace/src");
        assert!(fx.read(Path::new("/workspace/src/main.rs")).is_ok());
        assert!(matches!(
            fx.read(Path::new("/etc/passwd")),
            Err(EffectError::PathViolation(_))
        ));
        assert!(matches!(
            fx.read(Path::new("/workspace/secrets")),
            Err(EffectError::PathViolation(_))
        ));
    }

    #[test]
    fn allow_list_url_prefix_enforcement() {
        let fx = AllowListEffects::new().allow_url("https://docs.rs/");
        assert!(fx.fetch("https://docs.rs/portcullis").is_ok());
        assert!(matches!(
            fx.fetch("https://evil.com/exfil"),
            Err(EffectError::PolicyDenied(_))
        ));
    }

    // ── PolicyEnforced — policy gate ──────────────────────────────────────

    #[test]
    fn policy_enforced_denies_when_capability_is_never() {
        let policy = CapabilityLattice::bottom();
        let fx = PolicyEnforced {
            inner: RecordingEffects::new(),
            policy,
        };
        assert!(matches!(
            fx.read(Path::new("file.txt")),
            Err(EffectError::PolicyDenied(_))
        ));
        assert!(matches!(
            fx.fetch("https://example.com"),
            Err(EffectError::PolicyDenied(_))
        ));
        assert!(matches!(fx.run("ls"), Err(EffectError::PolicyDenied(_))));
        assert!(matches!(
            fx.commit("msg"),
            Err(EffectError::PolicyDenied(_))
        ));
        assert!(matches!(
            fx.push("origin", "main"),
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
            policy,
        };
        // These should reach the inner impl
        assert!(fx.read(Path::new("file.txt")).is_ok());
        assert!(fx.glob("*.rs").is_ok());
        assert_eq!(fx.inner.calls().len(), 2);
        // But web_fetch is still Never
        assert!(matches!(
            fx.fetch("https://example.com"),
            Err(EffectError::PolicyDenied(_))
        ));
    }

    #[test]
    fn production_effects_requires_policy() {
        let policy = CapabilityLattice::bottom();
        let fx = production_effects(policy);
        // Everything denied — confirming production_effects wraps in PolicyEnforced
        assert!(matches!(
            fx.read(Path::new("any.txt")),
            Err(EffectError::PolicyDenied(_))
        ));
    }

    #[test]
    fn production_effects_allows_read_when_policy_permits() {
        let mut policy = CapabilityLattice::bottom();
        policy.read_files = CapabilityLevel::Always;

        let fx = production_effects(policy);
        // Should pass the policy gate — will fail at I/O level (file missing)
        let result = fx.read(Path::new("/nonexistent/path/to/missing.txt"));
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
            fx.fetch("https://example.com"),
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
        fx.write(&path, b"hello effects").unwrap();
        let bytes = fx.read(&path).unwrap();
        assert_eq!(bytes, b"hello effects");
    }

    #[test]
    fn real_shell_runs_through_policy() {
        let mut policy = CapabilityLattice::bottom();
        policy.run_bash = CapabilityLevel::Always;
        let fx = production_effects(policy);
        let out = fx.run("echo nucleus").unwrap();
        assert!(out.success());
        assert!(out.stdout_str().contains("nucleus"));
    }
}
