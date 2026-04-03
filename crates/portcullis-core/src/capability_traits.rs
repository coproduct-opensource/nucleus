//! Compile-time capability marker traits (#1119, part of #1103).
//!
//! Sealed marker traits for each capability dimension. When combined with
//! a phantom-typed `Context<Caps>`, these enable compile-time enforcement:
//! a function requiring `HasWebFetch` won't compile if called from a
//! context that doesn't include that capability.
//!
//! ```rust,ignore
//! fn fetch_url<C: HasWebFetch>(ctx: &Context<C>) -> String { ... }
//!
//! // Compiles: codegen profile includes WebFetch
//! fetch_url(&codegen_ctx);
//!
//! // ERROR: code_review profile does not include WebFetch
//! fetch_url(&review_ctx);
//! ```

/// Sealed trait module — prevents external implementations.
mod sealed {
    pub trait Sealed {}
}

/// Marker: capability set includes file read access.
pub trait HasFileRead: sealed::Sealed {}

/// Marker: capability set includes file write access.
pub trait HasFileWrite: sealed::Sealed {}

/// Marker: capability set includes file edit access.
pub trait HasFileEdit: sealed::Sealed {}

/// Marker: capability set includes bash execution.
pub trait HasBashExec: sealed::Sealed {}

/// Marker: capability set includes glob search.
pub trait HasGlobSearch: sealed::Sealed {}

/// Marker: capability set includes grep search.
pub trait HasGrepSearch: sealed::Sealed {}

/// Marker: capability set includes web search.
pub trait HasWebSearch: sealed::Sealed {}

/// Marker: capability set includes web fetch.
pub trait HasWebFetch: sealed::Sealed {}

/// Marker: capability set includes git commit.
pub trait HasGitCommit: sealed::Sealed {}

/// Marker: capability set includes git push.
pub trait HasGitPush: sealed::Sealed {}

/// Marker: capability set includes PR creation.
pub trait HasCreatePr: sealed::Sealed {}

/// Marker: capability set includes pod management.
pub trait HasManagePods: sealed::Sealed {}

// ═══════════════════════════════════════════════════════════════════════════
// Concrete capability sets — these implement the marker traits
// ═══════════════════════════════════════════════════════════════════════════

/// Read-only capability set.
pub struct ReadOnly;
impl sealed::Sealed for ReadOnly {}
impl HasFileRead for ReadOnly {}
impl HasGlobSearch for ReadOnly {}
impl HasGrepSearch for ReadOnly {}

/// Code review capability set (read + web).
pub struct CodeReview;
impl sealed::Sealed for CodeReview {}
impl HasFileRead for CodeReview {}
impl HasGlobSearch for CodeReview {}
impl HasGrepSearch for CodeReview {}
impl HasWebFetch for CodeReview {}
impl HasWebSearch for CodeReview {}

/// Code generation capability set (read + write + bash, no network).
pub struct Codegen;
impl sealed::Sealed for Codegen {}
impl HasFileRead for Codegen {}
impl HasFileWrite for Codegen {}
impl HasFileEdit for Codegen {}
impl HasBashExec for Codegen {}
impl HasGlobSearch for Codegen {}
impl HasGrepSearch for Codegen {}
impl HasGitCommit for Codegen {}

/// Full capability set (all capabilities).
pub struct FullAccess;
impl sealed::Sealed for FullAccess {}
impl HasFileRead for FullAccess {}
impl HasFileWrite for FullAccess {}
impl HasFileEdit for FullAccess {}
impl HasBashExec for FullAccess {}
impl HasGlobSearch for FullAccess {}
impl HasGrepSearch for FullAccess {}
impl HasWebSearch for FullAccess {}
impl HasWebFetch for FullAccess {}
impl HasGitCommit for FullAccess {}
impl HasGitPush for FullAccess {}
impl HasCreatePr for FullAccess {}
impl HasManagePods for FullAccess {}

// ═══════════════════════════════════════════════════════════════════════════
// Context<Caps> — phantom-typed execution context (#1120)
// ═══════════════════════════════════════════════════════════════════════════

/// A phantom-typed execution context carrying compile-time capability information.
///
/// The type parameter `Caps` determines which capabilities are available.
/// Functions requiring specific capabilities constrain `Caps` with marker traits:
///
/// ```rust,ignore
/// fn write_file<C: HasFileWrite>(ctx: &Context<C>, path: &str, data: &[u8]) { ... }
/// ```
///
/// The context also carries runtime state (session ID, working directory)
/// that is independent of the capability type.
pub struct Context<Caps> {
    /// Session identifier for audit trail correlation.
    pub session_id: String,
    /// Working directory for file operations.
    pub work_dir: std::path::PathBuf,
    /// Phantom data carrying the capability type.
    _caps: std::marker::PhantomData<Caps>,
}

impl<Caps> Context<Caps> {
    /// Create a new context with the given session ID and working directory.
    pub fn new(session_id: String, work_dir: std::path::PathBuf) -> Self {
        Self {
            session_id,
            work_dir,
            _caps: std::marker::PhantomData,
        }
    }

    /// Get the session ID.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Get the working directory.
    pub fn work_dir(&self) -> &std::path::Path {
        &self.work_dir
    }
}

impl<Caps> std::fmt::Debug for Context<Caps> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context")
            .field("session_id", &self.session_id)
            .field("work_dir", &self.work_dir)
            .field("caps", &std::any::type_name::<Caps>())
            .finish()
    }
}

/// Create a read-only context.
pub fn read_only_context(session_id: String, work_dir: std::path::PathBuf) -> Context<ReadOnly> {
    Context::new(session_id, work_dir)
}

/// Create a code review context.
pub fn code_review_context(
    session_id: String,
    work_dir: std::path::PathBuf,
) -> Context<CodeReview> {
    Context::new(session_id, work_dir)
}

/// Create a code generation context.
pub fn codegen_context(session_id: String, work_dir: std::path::PathBuf) -> Context<Codegen> {
    Context::new(session_id, work_dir)
}

/// Create a full access context.
pub fn full_access_context(
    session_id: String,
    work_dir: std::path::PathBuf,
) -> Context<FullAccess> {
    Context::new(session_id, work_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    // These are compile-time tests — if they compile, the constraints work.
    fn requires_read<C: HasFileRead>(_cap: &C) {}
    fn requires_web_fetch<C: HasWebFetch>(_cap: &C) {}
    fn requires_bash<C: HasBashExec>(_cap: &C) {}
    fn requires_push<C: HasGitPush>(_cap: &C) {}

    #[test]
    fn read_only_has_read() {
        requires_read(&ReadOnly);
    }

    #[test]
    fn code_review_has_read_and_web() {
        requires_read(&CodeReview);
        requires_web_fetch(&CodeReview);
    }

    #[test]
    fn codegen_has_bash_no_web() {
        requires_bash(&Codegen);
        // requires_web_fetch(&Codegen);  // Would NOT compile — correct!
    }

    #[test]
    fn full_access_has_everything() {
        requires_read(&FullAccess);
        requires_web_fetch(&FullAccess);
        requires_bash(&FullAccess);
        requires_push(&FullAccess);
    }

    // ── Context<Caps> tests (#1120) ────────────────────────────────

    fn ctx_requires_read<C: HasFileRead>(ctx: &Context<C>) -> &str {
        ctx.session_id()
    }

    fn ctx_requires_web<C: HasWebFetch>(ctx: &Context<C>) -> &str {
        ctx.session_id()
    }

    #[test]
    fn read_only_context_has_read() {
        let ctx = read_only_context("sess1".into(), "/tmp".into());
        assert_eq!(ctx_requires_read(&ctx), "sess1");
    }

    #[test]
    fn code_review_context_has_web() {
        let ctx = code_review_context("sess2".into(), "/tmp".into());
        assert_eq!(ctx_requires_web(&ctx), "sess2");
    }

    #[test]
    fn codegen_context_has_bash() {
        let ctx = codegen_context("sess3".into(), "/work".into());
        requires_bash(&Codegen); // caps type has bash
        assert_eq!(ctx.work_dir().to_str().unwrap(), "/work");
    }

    #[test]
    fn context_debug_shows_caps_type() {
        let ctx = read_only_context("test".into(), "/tmp".into());
        let debug = format!("{ctx:?}");
        assert!(debug.contains("ReadOnly"));
        assert!(debug.contains("test"));
    }
}
