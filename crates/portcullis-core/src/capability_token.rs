//! PermRust-style capability tokens (#1320, #1348).
//!
//! Per-operation phantom tokens consumed on use. A token encodes WHICH
//! operation on WHICH resource was authorized. Reuse is a compile error
//! (move semantics). This unifies `Discharged<O>` with runtime authorization.
//!
//! ## Pattern
//!
//! Every `authorize()` call requires a `&DischargedBundle` — proof that
//! `preflight_action` ran and all obligations passed. Without a bundle,
//! you cannot mint a token. This connects the compile-time token system
//! to the runtime policy pipeline.
//!
//! ```rust
//! use portcullis_core::capability_token::ReadToken;
//! use portcullis_core::discharge::{preflight_action, ActionTerm, PreflightResult};
//! use portcullis_core::*;
//!
//! let term = ActionTerm {
//!     operation: Operation::WriteFiles,
//!     sink_class: SinkClass::WorkspaceWrite,
//!     source_labels: vec![],
//!     artifact_label: IFCLabel {
//!         confidentiality: ConfLevel::Internal,
//!         integrity: IntegLevel::Trusted,
//!         authority: AuthorityLevel::Directive,
//!         provenance: ProvenanceSet::SYSTEM,
//!         freshness: Freshness { observed_at: 1000, ttl_secs: 0 },
//!         derivation: DerivationClass::Deterministic,
//!     },
//!     subject: "spiffe://nucleus/agent/test".to_string(),
//!     estimated_cost_micro_usd: 0,
//! };
//!
//! if let PreflightResult::Allowed(bundle) = preflight_action(&term) {
//!     // Token minted with policy proof — can't be forged
//!     let token = ReadToken::authorize("config.toml", &bundle);
//!     assert_eq!(token.resource(), "config.toml");
//! }
//! ```

use std::marker::PhantomData;

use crate::discharge::DischargedBundle;

// ═══════════════════════════════════════════════════════════════════════════
// Operation tag types
// ═══════════════════════════════════════════════════════════════════════════

/// Tag for file read operations.
pub struct OpRead;
/// Tag for file write operations.
pub struct OpWrite;
/// Tag for shell execution.
pub struct OpShell;
/// Tag for web fetch operations.
pub struct OpFetch;
/// Tag for git commit operations.
pub struct OpGitCommit;
/// Tag for git push operations.
pub struct OpGitPush;

// ═══════════════════════════════════════════════════════════════════════════
// CapToken<Op> — the phantom-tagged capability token
// ═══════════════════════════════════════════════════════════════════════════

/// A capability token authorizing a specific operation on a specific resource.
///
/// - Phantom-tagged with `Op` (which operation)
/// - Carries the resource identifier (which target)
/// - NOT `Clone` or `Copy` — consumed on use (move semantics)
/// - Sealed constructor — only `authorize()` can create one
///
/// Per [PermRust](https://arxiv.org/pdf/2506.11701), capability tokens are
/// the key that unlocks I/O. Without the token, the operation can't proceed.
pub struct CapToken<Op> {
    resource: String,
    _op: PhantomData<Op>,
    _seal: Seal,
}

struct Seal;

impl<Op> CapToken<Op> {
    /// The authorized resource (path, URL, command, etc.).
    pub fn resource(&self) -> &str {
        &self.resource
    }

    /// Consume the token, returning the resource.
    ///
    /// After this call, the token no longer exists — it cannot be reused.
    pub fn consume(self) -> String {
        self.resource
    }

    /// Internal constructor — only callable from this module.
    fn mint(resource: impl Into<String>) -> Self {
        Self {
            resource: resource.into(),
            _op: PhantomData,
            _seal: Seal,
        }
    }
}

impl<Op> std::fmt::Debug for CapToken<Op> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CapToken<{}>({:?})",
            std::any::type_name::<Op>(),
            self.resource
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Type aliases for common operations
// ═══════════════════════════════════════════════════════════════════════════

/// Token authorizing a file read.
pub type ReadToken = CapToken<OpRead>;
/// Token authorizing a file write.
pub type WriteToken = CapToken<OpWrite>;
/// Token authorizing shell execution.
pub type ShellToken = CapToken<OpShell>;
/// Token authorizing a web fetch.
pub type FetchToken = CapToken<OpFetch>;
/// Token authorizing a git commit.
pub type GitCommitToken = CapToken<OpGitCommit>;
/// Token authorizing a git push.
pub type GitPushToken = CapToken<OpGitPush>;

// ═══════════════════════════════════════════════════════════════════════════
// Authorization constructors
// ═══════════════════════════════════════════════════════════════════════════

impl ReadToken {
    /// Authorize a file read on the given path.
    ///
    /// Requires a `&DischargedBundle` — proof that `preflight_action` passed.
    pub fn authorize(path: impl Into<String>, _proof: &DischargedBundle) -> Self {
        Self::mint(path)
    }
}

impl WriteToken {
    /// Authorize a file write on the given path.
    ///
    /// Requires a `&DischargedBundle` — proof that `preflight_action` passed.
    pub fn authorize(path: impl Into<String>, _proof: &DischargedBundle) -> Self {
        Self::mint(path)
    }
}

impl ShellToken {
    /// Authorize execution of the given command.
    ///
    /// Requires a `&DischargedBundle` — proof that `preflight_action` passed.
    pub fn authorize(command: impl Into<String>, _proof: &DischargedBundle) -> Self {
        Self::mint(command)
    }
}

impl FetchToken {
    /// Authorize fetching the given URL.
    ///
    /// Requires a `&DischargedBundle` — proof that `preflight_action` passed.
    pub fn authorize(url: impl Into<String>, _proof: &DischargedBundle) -> Self {
        Self::mint(url)
    }
}

impl GitCommitToken {
    /// Authorize a git commit with the given message.
    ///
    /// Requires a `&DischargedBundle` — proof that `preflight_action` passed.
    pub fn authorize(message: impl Into<String>, _proof: &DischargedBundle) -> Self {
        Self::mint(message)
    }
}

impl GitPushToken {
    /// Authorize a git push to the given remote.
    ///
    /// Requires a `&DischargedBundle` — proof that `preflight_action` passed.
    pub fn authorize(remote: impl Into<String>, _proof: &DischargedBundle) -> Self {
        Self::mint(remote)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discharge::{ActionTerm, PreflightResult, preflight_action};
    use crate::{
        AuthorityLevel, ConfLevel, DerivationClass, Freshness, IFCLabel, IntegLevel, Operation,
        ProvenanceSet, SinkClass,
    };

    /// Helper: produce a DischargedBundle by running preflight on a simple allowed term.
    fn proof() -> DischargedBundle {
        let term = ActionTerm {
            operation: Operation::WriteFiles,
            sink_class: SinkClass::WorkspaceWrite,
            source_labels: vec![],
            artifact_label: IFCLabel {
                confidentiality: ConfLevel::Internal,
                integrity: IntegLevel::Trusted,
                authority: AuthorityLevel::Directive,
                provenance: ProvenanceSet::SYSTEM,
                freshness: Freshness {
                    observed_at: 1000,
                    ttl_secs: 0,
                },
                derivation: DerivationClass::Deterministic,
            },
            subject: "spiffe://nucleus/agent/test".to_string(),
            estimated_cost_micro_usd: 0,
        };
        match preflight_action(&term) {
            PreflightResult::Allowed(bundle) => bundle,
            _ => panic!("expected Allowed"),
        }
    }

    #[test]
    fn read_token_carries_resource() {
        let bundle = proof();
        let token = ReadToken::authorize("config.toml", &bundle);
        assert_eq!(token.resource(), "config.toml");
    }

    #[test]
    fn token_consumed_on_use() {
        let bundle = proof();
        let token = WriteToken::authorize("output.txt", &bundle);
        let path = token.consume(); // token moved
        assert_eq!(path, "output.txt");
        // token.resource(); // would be compile error — moved
    }

    #[test]
    fn different_op_types_are_distinct() {
        let bundle = proof();
        let _read: ReadToken = ReadToken::authorize("file.rs", &bundle);
        let _write: WriteToken = WriteToken::authorize("file.rs", &bundle);
        // These are different types — can't mix them up
        // fn needs_write(_t: WriteToken) {}
        // needs_write(_read);  // COMPILE ERROR: expected WriteToken, got ReadToken
    }

    #[test]
    fn debug_shows_op_type() {
        let bundle = proof();
        let token = FetchToken::authorize("https://example.com", &bundle);
        let debug = format!("{token:?}");
        assert!(debug.contains("OpFetch"));
        assert!(debug.contains("example.com"));
    }

    #[test]
    fn shell_token_carries_command() {
        let bundle = proof();
        let token = ShellToken::authorize("cargo test", &bundle);
        assert_eq!(token.resource(), "cargo test");
    }

    #[test]
    fn git_push_token() {
        let bundle = proof();
        let token = GitPushToken::authorize("origin", &bundle);
        assert_eq!(token.consume(), "origin");
    }
}
