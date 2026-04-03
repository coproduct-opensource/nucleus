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
}
