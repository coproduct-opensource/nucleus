//! Compile-time capability marker traits (#1119, part of #1103).
//!
//! ## Primary surface: `portcullis-effects`
//!
//! For new code, prefer the `portcullis-effects` crate, which provides sealed
//! effect traits (`FileEffect`, `WebEffect`, `ShellEffect`, `GitEffect`) with
//! a `PolicyEnforced<E>` wrapper. That layer enforces the `CapabilityLattice`
//! at every method call — policy is structural, not a convention.
//!
//! The types in this module remain useful for compile-time phantom-type gating
//! (e.g., `fn requires_read<C: HasFileRead>(ctx: &Context<C>)`), but callers
//! performing real I/O should obtain effects via `production_effects(policy)`
//! from `portcullis-effects`, not call `std::fs` or `std::process` directly.
//!
//! ## Compile-time capability marker traits
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

/// Sealed trait module.
///
/// `pub` visibility is required for the `caps![]` macro to reference it
/// from external crates. The `Sealed` trait itself prevents external
/// implementations — only types created by `caps![]` or defined in this
/// module can implement it.
pub mod sealed {
    /// Sealing supertrait — prevents external capability set implementations.
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
// caps![] — ergonomic capability set declaration (#1122)
// ═══════════════════════════════════════════════════════════════════════════

/// Declare a custom capability set with specific marker traits.
///
/// Generates a zero-sized struct implementing `Sealed` and the listed
/// capability traits. This is the compile-time equivalent of the runtime
/// `CapabilityLattice::builder()`.
///
/// # Examples
///
/// ```rust
/// use portcullis_core::caps;
/// use portcullis_core::capability_traits::*;
///
/// // Define a custom capability set
/// caps!(MyResearchBot: HasFileRead, HasGlobSearch, HasGrepSearch, HasWebFetch);
///
/// // Use in trait bounds
/// fn fetch_docs<C: HasFileRead + HasWebFetch>(ctx: &Context<C>) -> String {
///     ctx.session_id().to_string()
/// }
///
/// let ctx = Context::<MyResearchBot>::new("sess".into(), "/tmp".into());
/// fetch_docs(&ctx); // compiles: MyResearchBot has both traits
/// ```
///
/// ```compile_fail
/// use portcullis_core::caps;
/// use portcullis_core::capability_traits::*;
///
/// caps!(ReadOnlyBot: HasFileRead, HasGlobSearch);
///
/// fn needs_bash<C: HasBashExec>(_ctx: &Context<C>) {}
///
/// let ctx = Context::<ReadOnlyBot>::new("s".into(), "/tmp".into());
/// needs_bash(&ctx); // ERROR: ReadOnlyBot doesn't have HasBashExec
/// ```
#[macro_export]
macro_rules! caps {
    ($name:ident : $($trait:ident),+ $(,)?) => {
        pub struct $name;
        impl $crate::capability_traits::sealed::Sealed for $name {}
        $(
            impl $crate::capability_traits::$trait for $name {}
        )+
    };
}

// Make the sealed module visible to the macro (pub(crate) → pub)
// The Sealed trait itself prevents external impl — the module visibility
// just lets the macro reference it.

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

// ═══════════════════════════════════════════════════════════════════════════
// Capability-bounded tool operations (#1121)
// ═══════════════════════════════════════════════════════════════════════════

/// Read a file — requires `HasFileRead` capability.
///
/// The compiler rejects calls from contexts missing file read access.
pub fn read_file<C: HasFileRead>(ctx: &Context<C>, path: &str) -> Result<String, String> {
    let full = ctx.work_dir().join(path);
    std::fs::read_to_string(&full).map_err(|e| format!("{}: {e}", full.display()))
}

/// Write a file — requires `HasFileWrite` capability.
pub fn write_file<C: HasFileWrite>(ctx: &Context<C>, path: &str, data: &str) -> Result<(), String> {
    let full = ctx.work_dir().join(path);
    std::fs::write(&full, data).map_err(|e| format!("{}: {e}", full.display()))
}

/// Search files by pattern — requires `HasGlobSearch` capability.
pub fn glob_search<C: HasGlobSearch>(
    _ctx: &Context<C>,
    _pattern: &str,
) -> Result<Vec<String>, String> {
    // Stub — real implementation would use glob crate
    Ok(vec![])
}

/// Search file contents — requires `HasGrepSearch` capability.
pub fn grep_search<C: HasGrepSearch>(
    _ctx: &Context<C>,
    _pattern: &str,
) -> Result<Vec<String>, String> {
    // Stub — real implementation would use regex
    Ok(vec![])
}

/// Fetch a URL — requires `HasWebFetch` capability.
pub fn web_fetch<C: HasWebFetch>(_ctx: &Context<C>, _url: &str) -> Result<String, String> {
    // Stub — real implementation would use reqwest
    Err("web_fetch not implemented in portcullis-core (use nucleus-tool-proxy)".into())
}

/// Execute a bash command — requires `HasBashExec` capability.
pub fn bash_exec<C: HasBashExec>(_ctx: &Context<C>, _cmd: &str) -> Result<String, String> {
    // Stub — real implementation would use std::process::Command
    Err("bash_exec not implemented in portcullis-core (use nucleus-tool-proxy)".into())
}

/// Git commit — requires `HasGitCommit` capability.
pub fn git_commit<C: HasGitCommit>(_ctx: &Context<C>, _message: &str) -> Result<(), String> {
    Err("git_commit not implemented in portcullis-core".into())
}

/// Git push — requires `HasGitPush` capability.
pub fn git_push<C: HasGitPush>(_ctx: &Context<C>) -> Result<(), String> {
    Err("git_push not implemented in portcullis-core".into())
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

    // ── Capability-bounded tool function tests (#1121) ─────────────

    #[test]
    fn read_file_compiles_for_read_only() {
        let dir = std::env::temp_dir();
        let ctx = read_only_context("test".into(), dir);
        // read_file compiles because ReadOnly has HasFileRead
        let _ = read_file(&ctx, "nonexistent.txt");
    }

    #[test]
    fn write_file_compiles_for_codegen() {
        let dir = std::env::temp_dir();
        let ctx = codegen_context("test".into(), dir);
        // write_file compiles because Codegen has HasFileWrite
        let _ = write_file(&ctx, "test.txt", "hello");
    }

    #[test]
    fn web_fetch_compiles_for_code_review() {
        let dir = std::env::temp_dir();
        let ctx = code_review_context("test".into(), dir);
        // web_fetch compiles because CodeReview has HasWebFetch
        let result = web_fetch(&ctx, "https://example.com");
        assert!(result.is_err()); // stub returns error
    }

    #[test]
    fn bash_exec_compiles_for_codegen() {
        let dir = std::env::temp_dir();
        let ctx = codegen_context("test".into(), dir);
        let result = bash_exec(&ctx, "echo hi");
        assert!(result.is_err()); // stub
    }

    // NOTE: The following would NOT compile — proving the type system works:
    // fn web_fetch_rejected_for_codegen() {
    //     let ctx = codegen_context("t".into(), "/tmp".into());
    //     web_fetch(&ctx, "https://evil.com");  // ERROR: Codegen lacks HasWebFetch
    // }
    // fn write_rejected_for_read_only() {
    //     let ctx = read_only_context("t".into(), "/tmp".into());
    //     write_file(&ctx, "file.txt", "data");  // ERROR: ReadOnly lacks HasFileWrite
    // }

    // ── caps![] macro tests (#1122) ───────────────────────────────────

    caps!(TestResearchBot: HasFileRead, HasGlobSearch, HasGrepSearch, HasWebFetch);

    #[test]
    fn caps_macro_creates_type_with_traits() {
        requires_read(&TestResearchBot);
        requires_web_fetch(&TestResearchBot);
    }

    #[test]
    fn caps_macro_type_works_with_context() {
        let ctx = Context::<TestResearchBot>::new("test".into(), "/tmp".into());
        assert_eq!(ctx_requires_read(&ctx), "test");
        assert_eq!(ctx_requires_web(&ctx), "test");
    }

    caps!(TestMinimalBot: HasFileRead);

    #[test]
    fn caps_macro_single_trait() {
        requires_read(&TestMinimalBot);
        // requires_bash(&TestMinimalBot);  // would NOT compile
    }

    caps!(TestFullBot: HasFileRead, HasFileWrite, HasFileEdit, HasBashExec,
          HasGlobSearch, HasGrepSearch, HasWebSearch, HasWebFetch,
          HasGitCommit, HasGitPush, HasCreatePr, HasManagePods);

    #[test]
    fn caps_macro_all_traits() {
        requires_read(&TestFullBot);
        requires_web_fetch(&TestFullBot);
        requires_bash(&TestFullBot);
        requires_push(&TestFullBot);
    }
}
