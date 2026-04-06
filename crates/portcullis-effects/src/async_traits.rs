//! Async effect traits for tokio-based I/O (#1277).
//!
//! Mirrors the sync traits (`FileEffect`, `WebEffect`, `ShellEffect`,
//! `GitEffect`, `AgentSpawnEffect`) with async versions for use in
//! `nucleus-tool-proxy` and other async callers.
//!
//! Gated behind the `async` feature flag to keep the default crate
//! dependency-free of tokio.

use std::path::{Path, PathBuf};

use crate::{EffectError, SearchResult, ShellOutput};

/// Async file system operations.
pub trait AsyncFileEffect {
    /// Read the full contents of a file.
    fn read(
        &self,
        path: &Path,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, EffectError>> + Send;

    /// Write bytes to a file, creating it if it does not exist.
    fn write(
        &self,
        path: &Path,
        content: &[u8],
    ) -> impl std::future::Future<Output = Result<(), EffectError>> + Send;

    /// Append bytes to a file, creating it if it does not exist.
    fn append(
        &self,
        path: &Path,
        content: &[u8],
    ) -> impl std::future::Future<Output = Result<(), EffectError>> + Send;

    /// List files matching a glob pattern. Returns absolute paths.
    fn glob(
        &self,
        pattern: &str,
    ) -> impl std::future::Future<Output = Result<Vec<PathBuf>, EffectError>> + Send;
}

/// Async web fetch and search operations.
pub trait AsyncWebEffect {
    /// Fetch the body of a URL. Returns raw bytes.
    fn fetch(
        &self,
        url: &str,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, EffectError>> + Send;

    /// Perform a web search and return result snippets.
    fn search(
        &self,
        query: &str,
    ) -> impl std::future::Future<Output = Result<Vec<SearchResult>, EffectError>> + Send;
}

/// Async shell command execution.
pub trait AsyncShellEffect {
    /// Run a shell command and return stdout/stderr.
    fn run(
        &self,
        cmd: &str,
    ) -> impl std::future::Future<Output = Result<ShellOutput, EffectError>> + Send;
}

/// Async git operations.
pub trait AsyncGitEffect {
    /// Create a git commit with the given message.
    fn commit(
        &self,
        message: &str,
    ) -> impl std::future::Future<Output = Result<String, EffectError>> + Send;

    /// Push the current branch to a remote.
    fn push(
        &self,
        remote: &str,
        branch: &str,
    ) -> impl std::future::Future<Output = Result<(), EffectError>> + Send;
}

/// Async sub-agent spawn operations.
pub trait AsyncAgentSpawnEffect {
    /// Spawn a sub-agent at the given endpoint with the given term.
    fn spawn(
        &self,
        endpoint: &str,
        term_json: &str,
    ) -> impl std::future::Future<Output = Result<String, EffectError>> + Send;
}

// ═══════════════════════════════════════════════════════════════════════════
// Blanket: sync → async adapter
// ═══════════════════════════════════════════════════════════════════════════

/// Wraps a sync effect handler to satisfy async trait bounds.
///
/// The async methods call the sync methods directly (no spawning).
/// This is useful for tests and for callers that don't need real async.
pub struct SyncAdapter<E>(pub E);

impl<E: crate::FileEffect + Send + Sync> AsyncFileEffect for SyncAdapter<E> {
    async fn read(&self, path: &Path) -> Result<Vec<u8>, EffectError> {
        self.0.read(path)
    }
    async fn write(&self, path: &Path, content: &[u8]) -> Result<(), EffectError> {
        self.0.write(path, content)
    }
    async fn append(&self, path: &Path, content: &[u8]) -> Result<(), EffectError> {
        self.0.append(path, content)
    }
    async fn glob(&self, pattern: &str) -> Result<Vec<PathBuf>, EffectError> {
        self.0.glob(pattern)
    }
}

impl<E: crate::WebEffect + Send + Sync> AsyncWebEffect for SyncAdapter<E> {
    async fn fetch(&self, url: &str) -> Result<Vec<u8>, EffectError> {
        self.0.fetch(url)
    }
    async fn search(&self, query: &str) -> Result<Vec<SearchResult>, EffectError> {
        self.0.search(query)
    }
}

impl<E: crate::ShellEffect + Send + Sync> AsyncShellEffect for SyncAdapter<E> {
    async fn run(&self, cmd: &str) -> Result<ShellOutput, EffectError> {
        self.0.run(cmd)
    }
}

impl<E: crate::GitEffect + Send + Sync> AsyncGitEffect for SyncAdapter<E> {
    async fn commit(&self, message: &str) -> Result<String, EffectError> {
        self.0.commit(message)
    }
    async fn push(&self, remote: &str, branch: &str) -> Result<(), EffectError> {
        self.0.push(remote, branch)
    }
}

impl<E: crate::AgentSpawnEffect + Send + Sync> AsyncAgentSpawnEffect for SyncAdapter<E> {
    async fn spawn(&self, endpoint: &str, term_json: &str) -> Result<String, EffectError> {
        self.0.spawn(endpoint, term_json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DenyAllEffects;

    #[test]
    fn sync_adapter_wraps_deny_all() {
        // SyncAdapter<DenyAllEffects> implements all async traits.
        // We can't easily test async in sync tests, but we verify it compiles.
        let _adapter = SyncAdapter(DenyAllEffects);
    }
}
