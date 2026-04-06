//! Type-level IFC — phantom `IntegLevel`/`ConfLevel` on data values (#1192).
//!
//! [`Labeled<T, I, C>`] encodes integrity and confidentiality as phantom type
//! parameters. The compiler — not the runtime — prevents tainted data from
//! flowing to clean sinks.
//!
//! ## Design
//!
//! ```text
//! Labeled<String, Adversarial, Public>   ← web fetch output
//! Labeled<Vec<u8>, Trusted, Internal>    ← file read output
//! Labeled<String, Trusted, Secret>       ← env var read
//! ```
//!
//! Flow rules are expressed as trait bounds:
//! - `fn exec_shell<I: IntegAtLeast<Untrusted>>(cmd: Labeled<String, I, Public>)`
//!   → rejects `Adversarial` input at compile time
//! - `fn publish<C: ConfAtMost<Internal>>(data: Labeled<T, Trusted, C>)`
//!   → rejects `Secret` data at compile time
//!
//! ## Relationship to runtime labels
//!
//! The runtime [`crate::IFCLabel`] handles dynamic joins on the flow graph.
//! `Labeled<T, I, C>` is a **compile-time approximation** that catches
//! "obvious" violations statically. Both coexist: type-level catches
//! structural errors at compile time; runtime catches data-dependent flows.

use std::marker::PhantomData;

// ═══════════════════════════════════════════════════════════════════════════
// Sealing
// ═══════════════════════════════════════════════════════════════════════════

mod sealed {
    pub trait IntegSealed {}
    pub trait ConfSealed {}
}

// ═══════════════════════════════════════════════════════════════════════════
// Integrity tag types (zero-sized)
// ═══════════════════════════════════════════════════════════════════════════

/// Tag trait for integrity levels. Sealed — only the three built-in tags
/// implement this.
pub trait IntegTag: sealed::IntegSealed {
    /// The corresponding runtime `IntegLevel`.
    fn runtime_level() -> crate::IntegLevel;
}

/// Trusted integrity — user prompts, system config, verified sources.
pub struct Trusted;
impl sealed::IntegSealed for Trusted {}
impl IntegTag for Trusted {
    fn runtime_level() -> crate::IntegLevel {
        crate::IntegLevel::Trusted
    }
}

/// Untrusted integrity — MCP tool output, cached data.
pub struct Untrusted;
impl sealed::IntegSealed for Untrusted {}
impl IntegTag for Untrusted {
    fn runtime_level() -> crate::IntegLevel {
        crate::IntegLevel::Untrusted
    }
}

/// Adversarial integrity — web content, public issues.
pub struct Adversarial;
impl sealed::IntegSealed for Adversarial {}
impl IntegTag for Adversarial {
    fn runtime_level() -> crate::IntegLevel {
        crate::IntegLevel::Adversarial
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Confidentiality tag types (zero-sized)
// ═══════════════════════════════════════════════════════════════════════════

/// Tag trait for confidentiality levels. Sealed.
pub trait ConfTag: sealed::ConfSealed {
    /// The corresponding runtime `ConfLevel`.
    fn runtime_level() -> crate::ConfLevel;
}

/// Public confidentiality — web content, public repos, docs.
pub struct Public;
impl sealed::ConfSealed for Public {}
impl ConfTag for Public {
    fn runtime_level() -> crate::ConfLevel {
        crate::ConfLevel::Public
    }
}

/// Internal confidentiality — private repos, user files, env vars.
pub struct Internal;
impl sealed::ConfSealed for Internal {}
impl ConfTag for Internal {
    fn runtime_level() -> crate::ConfLevel {
        crate::ConfLevel::Internal
    }
}

/// Secret confidentiality — API keys, credentials, PII.
pub struct Secret;
impl sealed::ConfSealed for Secret {}
impl ConfTag for Secret {
    fn runtime_level() -> crate::ConfLevel {
        crate::ConfLevel::Secret
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Flow rule traits — compile-time lattice constraints
// ═══════════════════════════════════════════════════════════════════════════

/// Integrity at least `Floor` — the value's integrity is ≥ Floor.
///
/// ```text
/// IntegAtLeast<Adversarial>  ← Adversarial, Untrusted, Trusted all satisfy
/// IntegAtLeast<Untrusted>    ← Untrusted, Trusted satisfy; Adversarial does NOT
/// IntegAtLeast<Trusted>      ← only Trusted satisfies
/// ```
///
/// Use this as a trait bound on function parameters to enforce minimum
/// integrity at compile time.
pub trait IntegAtLeast<Floor: IntegTag>: IntegTag {}

// Adversarial floor — everything passes (bottom of the lattice)
impl IntegAtLeast<Adversarial> for Adversarial {}
impl IntegAtLeast<Adversarial> for Untrusted {}
impl IntegAtLeast<Adversarial> for Trusted {}

// Untrusted floor — Adversarial does NOT pass
impl IntegAtLeast<Untrusted> for Untrusted {}
impl IntegAtLeast<Untrusted> for Trusted {}

// Trusted floor — only Trusted passes
impl IntegAtLeast<Trusted> for Trusted {}

/// Confidentiality at most `Ceiling` — the value's conf is ≤ Ceiling.
///
/// ```text
/// ConfAtMost<Secret>    ← Public, Internal, Secret all satisfy
/// ConfAtMost<Internal>  ← Public, Internal satisfy; Secret does NOT
/// ConfAtMost<Public>    ← only Public satisfies
/// ```
///
/// Use this to enforce downflow containment: secret data cannot
/// flow to a public sink.
pub trait ConfAtMost<Ceiling: ConfTag>: ConfTag {}

// Secret ceiling — everything passes (top of the lattice)
impl ConfAtMost<Secret> for Public {}
impl ConfAtMost<Secret> for Internal {}
impl ConfAtMost<Secret> for Secret {}

// Internal ceiling — Secret does NOT pass
impl ConfAtMost<Internal> for Public {}
impl ConfAtMost<Internal> for Internal {}

// Public ceiling — only Public passes
impl ConfAtMost<Public> for Public {}

// ═══════════════════════════════════════════════════════════════════════════
// Labeled<T, I, C> — the phantom-tagged newtype
// ═══════════════════════════════════════════════════════════════════════════

/// A value `T` tagged with compile-time integrity `I` and confidentiality `C`.
///
/// `Labeled` is the bridge between the type system and the IFC lattice.
/// It cannot be constructed without specifying both tags, and the tags
/// cannot be changed without going through [`declassify`] (which requires
/// an explicit policy argument).
///
/// ## Construction
///
/// ```rust
/// use portcullis_core::labeled::{Labeled, Trusted, Public};
///
/// let data: Labeled<String, Trusted, Public> = Labeled::new("hello".to_string());
/// assert_eq!(data.inner(), "hello");
/// ```
///
/// ## Flow constraints
///
/// ```compile_fail
/// use portcullis_core::labeled::{Labeled, Adversarial, Trusted, Public, IntegAtLeast};
///
/// fn requires_trusted<I: IntegAtLeast<Trusted>>(val: Labeled<String, I, Public>) {}
///
/// let web_data: Labeled<String, Adversarial, Public> = Labeled::new("evil".to_string());
/// requires_trusted(web_data); // ERROR: Adversarial does not implement IntegAtLeast<Trusted>
/// ```
pub struct Labeled<T, I: IntegTag, C: ConfTag> {
    value: T,
    _integ: PhantomData<I>,
    _conf: PhantomData<C>,
}

impl<T, I: IntegTag, C: ConfTag> Labeled<T, I, C> {
    /// Wrap a value with the given integrity and confidentiality tags.
    pub fn new(value: T) -> Self {
        Self {
            value,
            _integ: PhantomData,
            _conf: PhantomData,
        }
    }

    /// Borrow the inner value.
    pub fn inner(&self) -> &T {
        &self.value
    }

    /// Consume the wrapper and return the inner value.
    ///
    /// **Security note**: this discards the IFC tags. Use only at
    /// trusted boundaries where the data's labels have already been
    /// verified (e.g., after a successful `preflight_action` call).
    pub fn into_inner(self) -> T {
        self.value
    }

    /// Map the inner value while preserving the IFC tags.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Labeled<U, I, C> {
        Labeled::new(f(self.value))
    }

    /// The runtime integrity level corresponding to this tag.
    pub fn integrity_level(&self) -> crate::IntegLevel {
        I::runtime_level()
    }

    /// The runtime confidentiality level corresponding to this tag.
    pub fn conf_level(&self) -> crate::ConfLevel {
        C::runtime_level()
    }
}

impl<T: Clone, I: IntegTag, C: ConfTag> Clone for Labeled<T, I, C> {
    fn clone(&self) -> Self {
        Self::new(self.value.clone())
    }
}

impl<T: std::fmt::Debug, I: IntegTag, C: ConfTag> std::fmt::Debug for Labeled<T, I, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Labeled")
            .field("value", &self.value)
            .field("integrity", &I::runtime_level())
            .field("confidentiality", &C::runtime_level())
            .finish()
    }
}

impl<T: PartialEq, I: IntegTag, C: ConfTag> PartialEq for Labeled<T, I, C> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<T: Eq, I: IntegTag, C: ConfTag> Eq for Labeled<T, I, C> {}

// ═══════════════════════════════════════════════════════════════════════════
// Upcast — weaken labels (always safe, no policy required)
// ═══════════════════════════════════════════════════════════════════════════

impl<T> Labeled<T, Trusted, Public> {
    /// Weaken trusted+public data to untrusted (safe: losing privilege).
    pub fn weaken_to_untrusted(self) -> Labeled<T, Untrusted, Public> {
        Labeled::new(self.value)
    }
}

impl<T, I: IntegTag> Labeled<T, I, Public> {
    /// Raise confidentiality from public to internal (safe: gaining restriction).
    pub fn raise_to_internal(self) -> Labeled<T, I, Internal> {
        Labeled::new(self.value)
    }
}

impl<T, I: IntegTag> Labeled<T, I, Internal> {
    /// Raise confidentiality from internal to secret (safe: gaining restriction).
    pub fn raise_to_secret(self) -> Labeled<T, I, Secret> {
        Labeled::new(self.value)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Declassify — strengthen labels (requires explicit policy)
// ═══════════════════════════════════════════════════════════════════════════

/// Reason for declassification — required for audit trail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeclassifyReason {
    /// Human reviewed and approved the content.
    HumanReview,
    /// Content was verified by a deterministic check (hash, signature).
    DeterministicVerification,
    /// Content was sanitized (e.g., HTML escaping, input validation).
    Sanitization,
    /// Testing or development — NOT for production use.
    TestOnly,
}

/// Error from a declassification attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeclassifyError {
    /// The reason is not sufficient for this declassification.
    InsufficientReason(String),
}

impl std::fmt::Display for DeclassifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientReason(msg) => write!(f, "declassification denied: {msg}"),
        }
    }
}

impl std::error::Error for DeclassifyError {}

/// Promote adversarial data to untrusted after providing a reason.
///
/// This is an explicit integrity upgrade — the caller must justify why
/// the data can be considered non-adversarial. The reason is recorded
/// for audit purposes.
///
/// To promote to `Trusted`, call `promote_to_trusted` on the result.
pub fn promote_integrity<T, C: ConfTag>(
    value: Labeled<T, Adversarial, C>,
    reason: DeclassifyReason,
) -> Result<Labeled<T, Untrusted, C>, DeclassifyError> {
    match reason {
        DeclassifyReason::HumanReview
        | DeclassifyReason::DeterministicVerification
        | DeclassifyReason::Sanitization => Ok(Labeled::new(value.into_inner())),
        DeclassifyReason::TestOnly => Err(DeclassifyError::InsufficientReason(
            "TestOnly cannot promote integrity — use HumanReview, \
             DeterministicVerification, or Sanitization"
                .to_string(),
        )),
    }
}

/// Promote untrusted data to trusted after providing a reason.
///
/// Only `HumanReview` and `DeterministicVerification` are accepted
/// for promotion to `Trusted`. `Sanitization` alone is not sufficient.
pub fn promote_to_trusted<T, C: ConfTag>(
    value: Labeled<T, Untrusted, C>,
    reason: DeclassifyReason,
) -> Result<Labeled<T, Trusted, C>, DeclassifyError> {
    match reason {
        DeclassifyReason::HumanReview | DeclassifyReason::DeterministicVerification => {
            Ok(Labeled::new(value.into_inner()))
        }
        DeclassifyReason::Sanitization => Err(DeclassifyError::InsufficientReason(
            "sanitization alone is not sufficient to promote to Trusted; \
             use HumanReview or DeterministicVerification"
                .to_string(),
        )),
        DeclassifyReason::TestOnly => Err(DeclassifyError::InsufficientReason(
            "TestOnly cannot promote to Trusted in production".to_string(),
        )),
    }
}

/// Lower confidentiality from secret to internal (declassification).
///
/// Only `HumanReview` is accepted for confidentiality downgrade.
pub fn declassify_to_internal<T, I: IntegTag>(
    value: Labeled<T, I, Secret>,
    reason: DeclassifyReason,
) -> Result<Labeled<T, I, Internal>, DeclassifyError> {
    match reason {
        DeclassifyReason::HumanReview => Ok(Labeled::new(value.into_inner())),
        other => Err(DeclassifyError::InsufficientReason(format!(
            "{other:?} is not sufficient to declassify Secret → Internal; \
             only HumanReview is accepted"
        ))),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Construction and access ─────────────────────────────────────────

    #[test]
    fn labeled_wraps_and_unwraps() {
        let data: Labeled<String, Trusted, Public> = Labeled::new("hello".to_string());
        assert_eq!(data.inner(), "hello");
        assert_eq!(data.into_inner(), "hello");
    }

    #[test]
    fn labeled_map_preserves_tags() {
        let data: Labeled<String, Adversarial, Public> = Labeled::new("hello".to_string());
        let upper: Labeled<String, Adversarial, Public> = data.map(|s| s.to_uppercase());
        assert_eq!(upper.inner(), "HELLO");
    }

    #[test]
    fn labeled_clone() {
        let data: Labeled<String, Trusted, Internal> = Labeled::new("test".to_string());
        let cloned = data.clone();
        assert_eq!(cloned.inner(), "test");
    }

    #[test]
    fn runtime_levels_match() {
        let data: Labeled<(), Trusted, Secret> = Labeled::new(());
        assert_eq!(data.integrity_level(), crate::IntegLevel::Trusted);
        assert_eq!(data.conf_level(), crate::ConfLevel::Secret);
    }

    // ── Flow constraint trait bounds ────────────────────────────────────

    fn requires_trusted_or_higher<I: IntegAtLeast<Trusted>, C: ConfTag>(
        _val: &Labeled<String, I, C>,
    ) {
    }

    fn requires_untrusted_or_higher<I: IntegAtLeast<Untrusted>, C: ConfTag>(
        _val: &Labeled<String, I, C>,
    ) {
    }

    fn requires_public_conf<I: IntegTag, C: ConfAtMost<Public>>(_val: &Labeled<String, I, C>) {}

    fn requires_internal_or_lower<I: IntegTag, C: ConfAtMost<Internal>>(
        _val: &Labeled<String, I, C>,
    ) {
    }

    #[test]
    fn trusted_passes_trusted_gate() {
        let data: Labeled<String, Trusted, Public> = Labeled::new("safe".to_string());
        requires_trusted_or_higher(&data);
    }

    #[test]
    fn trusted_passes_untrusted_gate() {
        let data: Labeled<String, Trusted, Public> = Labeled::new("safe".to_string());
        requires_untrusted_or_higher(&data);
    }

    #[test]
    fn untrusted_passes_untrusted_gate() {
        let data: Labeled<String, Untrusted, Public> = Labeled::new("tool".to_string());
        requires_untrusted_or_higher(&data);
    }

    #[test]
    fn public_passes_public_conf_gate() {
        let data: Labeled<String, Trusted, Public> = Labeled::new("public".to_string());
        requires_public_conf(&data);
    }

    #[test]
    fn internal_passes_internal_conf_gate() {
        let data: Labeled<String, Trusted, Internal> = Labeled::new("file".to_string());
        requires_internal_or_lower(&data);
    }

    #[test]
    fn public_passes_internal_conf_gate() {
        let data: Labeled<String, Trusted, Public> = Labeled::new("web".to_string());
        requires_internal_or_lower(&data);
    }

    // ── Compile-fail: these would NOT compile if uncommented ────────────
    //
    // #[test]
    // fn adversarial_rejected_at_trusted_gate() {
    //     let data: Labeled<String, Adversarial, Public> = Labeled::new("evil".to_string());
    //     requires_trusted_or_higher(&data);  // ERROR: Adversarial !: IntegAtLeast<Trusted>
    // }
    //
    // #[test]
    // fn secret_rejected_at_public_gate() {
    //     let data: Labeled<String, Trusted, Secret> = Labeled::new("key".to_string());
    //     requires_public_conf(&data);  // ERROR: Secret !: ConfAtMost<Public>
    // }

    // ── Upcast (weakening) ──────────────────────────────────────────────

    #[test]
    fn weaken_trusted_to_untrusted() {
        let data: Labeled<String, Trusted, Public> = Labeled::new("safe".to_string());
        let weakened: Labeled<String, Untrusted, Public> = data.weaken_to_untrusted();
        assert_eq!(weakened.inner(), "safe");
    }

    #[test]
    fn raise_public_to_internal() {
        let data: Labeled<String, Trusted, Public> = Labeled::new("data".to_string());
        let raised: Labeled<String, Trusted, Internal> = data.raise_to_internal();
        assert_eq!(raised.inner(), "data");
    }

    #[test]
    fn raise_internal_to_secret() {
        let data: Labeled<String, Trusted, Internal> = Labeled::new("data".to_string());
        let raised: Labeled<String, Trusted, Secret> = data.raise_to_secret();
        assert_eq!(raised.inner(), "data");
    }

    // ── Declassification ────────────────────────────────────────────────

    #[test]
    fn promote_adversarial_to_untrusted_with_human_review() {
        let web: Labeled<String, Adversarial, Public> = Labeled::new("web data".to_string());
        let promoted = promote_integrity(web, DeclassifyReason::HumanReview).unwrap();
        assert_eq!(promoted.inner(), "web data");
        assert_eq!(promoted.integrity_level(), crate::IntegLevel::Untrusted);
    }

    #[test]
    fn promote_untrusted_to_trusted_with_deterministic_verification() {
        let tool: Labeled<String, Untrusted, Public> = Labeled::new("verified".to_string());
        let promoted =
            promote_to_trusted(tool, DeclassifyReason::DeterministicVerification).unwrap();
        assert_eq!(promoted.integrity_level(), crate::IntegLevel::Trusted);
    }

    #[test]
    fn promote_untrusted_to_trusted_rejects_sanitization() {
        let tool: Labeled<String, Untrusted, Public> = Labeled::new("sanitized".to_string());
        let err = promote_to_trusted(tool, DeclassifyReason::Sanitization).unwrap_err();
        assert!(matches!(err, DeclassifyError::InsufficientReason(_)));
    }

    #[test]
    fn declassify_secret_to_internal_with_human_review() {
        let secret: Labeled<String, Trusted, Secret> = Labeled::new("api-key".to_string());
        let declassified = declassify_to_internal(secret, DeclassifyReason::HumanReview).unwrap();
        assert_eq!(declassified.conf_level(), crate::ConfLevel::Internal);
    }

    #[test]
    fn declassify_secret_rejects_test_only() {
        let secret: Labeled<String, Trusted, Secret> = Labeled::new("api-key".to_string());
        let err = declassify_to_internal(secret, DeclassifyReason::TestOnly).unwrap_err();
        assert!(matches!(err, DeclassifyError::InsufficientReason(_)));
    }

    #[test]
    fn promote_integrity_rejects_test_only() {
        let adv: Labeled<String, Adversarial, Public> = Labeled::new("web data".to_string());
        let err = promote_integrity(adv, DeclassifyReason::TestOnly).unwrap_err();
        assert!(matches!(err, DeclassifyError::InsufficientReason(_)));
    }

    // ── Debug output ────────────────────────────────────────────────────

    #[test]
    fn debug_shows_tags() {
        let data: Labeled<&str, Adversarial, Secret> = Labeled::new("secret web data");
        let debug = format!("{data:?}");
        assert!(debug.contains("Adversarial"));
        assert!(debug.contains("Secret"));
    }

    // ── Full round-trip: web → promote → gate ───────────────────────────

    #[test]
    fn web_data_promoted_through_pipeline() {
        // Web fetch returns adversarial data
        let web: Labeled<String, Adversarial, Public> = Labeled::new("scraped content".to_string());

        // Cannot pass to trusted gate directly (compile error if uncommented):
        // requires_trusted_or_higher(&web);

        // Promote to untrusted after human review
        let reviewed = promote_integrity(web, DeclassifyReason::HumanReview).unwrap();
        requires_untrusted_or_higher(&reviewed); // Now passes

        // Promote to trusted after deterministic verification
        let verified =
            promote_to_trusted(reviewed, DeclassifyReason::DeterministicVerification).unwrap();
        requires_trusted_or_higher(&verified); // Now passes
    }
}
