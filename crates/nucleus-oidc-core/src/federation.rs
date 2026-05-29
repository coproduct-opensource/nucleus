// SPDX-License-Identifier: MIT
//
//! Federation dispatch primitives.
//!
//! Composed of three pieces:
//!
//! 1. [`peek_jwt_issuer`] — extract a JWT's `iss` claim WITHOUT
//!    verifying its signature. Used by dispatchers that need to pick
//!    a per-provider validator before crypto runs. The downstream
//!    validator does the actual signature check.
//! 2. [`IssuerProvider`] trait — implemented per-provider in
//!    vendor-aware sibling crates. Each impl declares: (a) a stable
//!    name, (b) a predicate matching the `iss` URLs it serves, (c) a
//!    stable prefix for synthetic builder uids.
//! 3. [`FederationRegistry`] — holds the set of registered
//!    [`IssuerProvider`]s and dispatches by `iss`. Enforces name +
//!    prefix uniqueness at registration time.
//!
//! # Vendor-neutral by construction
//!
//! This module ships zero vendor URLs, names, or token shapes. The
//! per-provider impls live in sibling crates that depend on this one.
//! See `docs/oidc-vendor-neutrality-audit.md` for the rationale.

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::Deserialize;

use crate::error::OidcError;

/// Trait every per-provider crate implements to register itself with
/// the [`FederationRegistry`].
pub trait IssuerProvider: Send + Sync + std::fmt::Debug + 'static {
    /// Stable, human-readable name for logging + error messages
    /// (e.g. `"alpha-idp"`, `"beta-idp"`).
    fn name(&self) -> &'static str;
    /// Does this provider claim the given `iss` URL?
    fn matches(&self, iss: &str) -> bool;
    /// Per-provider stable prefix for [`FederationRegistry::synthetic_uid`]
    /// (e.g. `"b-a-"`, `"b-b-"`).
    fn uid_prefix(&self) -> &'static str;
}

/// Registry providers register into at startup.
///
/// `register` enforces uniqueness on BOTH the provider name AND the
/// `uid_prefix` so two providers can never claim the same synthetic
/// uid space.
#[derive(Default)]
pub struct FederationRegistry {
    providers: Vec<Arc<dyn IssuerProvider>>,
}

impl FederationRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a provider. Fails with [`OidcError::FederationConflict`]
    /// if another already-registered provider has the same `name()` or
    /// `uid_prefix()`.
    pub fn register(&mut self, provider: Arc<dyn IssuerProvider>) -> Result<(), OidcError> {
        for existing in &self.providers {
            if existing.name() == provider.name() {
                return Err(OidcError::FederationConflict(format!(
                    "duplicate provider name {:?}",
                    provider.name()
                )));
            }
            if existing.uid_prefix() == provider.uid_prefix() {
                return Err(OidcError::FederationConflict(format!(
                    "duplicate uid_prefix {:?}",
                    provider.uid_prefix()
                )));
            }
        }
        self.providers.push(provider);
        Ok(())
    }

    /// First registered provider matching `iss`, or `None`.
    pub fn classify(&self, iss: &str) -> Option<&dyn IssuerProvider> {
        for p in &self.providers {
            if p.matches(iss) {
                return Some(p.as_ref());
            }
        }
        None
    }

    /// Mint a synthetic uid for `(iss, scope)`: `{provider.uid_prefix}{sanitize(scope)}`.
    /// Returns `None` if no provider matches.
    pub fn synthetic_uid(&self, iss: &str, scope: &str) -> Option<String> {
        let provider = self.classify(iss)?;
        Some(format!(
            "{}{}",
            provider.uid_prefix(),
            sanitize_scope(scope)
        ))
    }

    /// All currently-registered providers, in registration order.
    /// Mainly for introspection / debug surfaces.
    pub fn providers(&self) -> impl Iterator<Item = &dyn IssuerProvider> {
        self.providers.iter().map(|p| p.as_ref())
    }
}

/// Normalize a per-provider scope string into a safe identifier
/// component. Keeps ASCII alphanumeric + `-` + `_`; replaces `/` with
/// `-` (so e.g. `owner/repo` → `owner-repo`); collapses all other
/// chars to `-`. Leading/trailing hyphens are trimmed.
pub fn sanitize_scope(scope: &str) -> String {
    let collected: String = scope
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' => c,
            '/' => '-',
            _ => '-',
        })
        .collect();
    collected.trim_matches('-').to_string()
}

/// Minimal payload shape for the issuer peek.
#[derive(Deserialize)]
struct IssuerPeek {
    iss: String,
}

/// Peek at the `iss` claim of an UNVERIFIED JWT, without checking the
/// signature.
///
/// The signature check is the validator's job, but the dispatcher
/// needs to know which validator to call BEFORE that. The worst a
/// malicious peek result can do is route to the wrong validator,
/// which then fails-closed on signature.
///
/// Errors on malformed input: not 3 dot-separated parts, payload not
/// base64url, payload not JSON, or `iss` claim missing.
pub fn peek_jwt_issuer(jwt: &str) -> Result<String, OidcError> {
    let mut parts = jwt.splitn(3, '.');
    let _header = parts
        .next()
        .ok_or_else(|| OidcError::JwtValidation("jwt missing header".into()))?;
    let payload_b64 = parts
        .next()
        .ok_or_else(|| OidcError::JwtValidation("jwt missing payload".into()))?;
    let _signature = parts
        .next()
        .ok_or_else(|| OidcError::JwtValidation("jwt missing signature".into()))?;
    if parts.next().is_some() {
        return Err(OidcError::JwtValidation("jwt has more than 3 parts".into()));
    }
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| OidcError::JwtValidation(format!("base64url decode: {e}")))?;
    let peek: IssuerPeek = serde_json::from_slice(&payload_bytes)
        .map_err(|e| OidcError::JwtValidation(format!("payload json: {e}")))?;
    Ok(peek.iss)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct FakeProvider {
        name: &'static str,
        prefix: &'static str,
        iss_prefix: &'static str,
    }

    impl IssuerProvider for FakeProvider {
        fn name(&self) -> &'static str {
            self.name
        }
        fn matches(&self, iss: &str) -> bool {
            iss.starts_with(self.iss_prefix)
        }
        fn uid_prefix(&self) -> &'static str {
            self.prefix
        }
    }

    fn provider(
        name: &'static str,
        prefix: &'static str,
        iss_prefix: &'static str,
    ) -> Arc<dyn IssuerProvider> {
        Arc::new(FakeProvider {
            name,
            prefix,
            iss_prefix,
        })
    }

    #[test]
    fn registry_dispatches_by_iss_match() {
        let mut reg = FederationRegistry::new();
        reg.register(provider("alpha", "b-a-", "https://alpha.example/"))
            .unwrap();
        reg.register(provider("beta", "b-b-", "https://beta.example/"))
            .unwrap();

        let p = reg.classify("https://alpha.example/issuer/x").unwrap();
        assert_eq!(p.name(), "alpha");

        let p = reg.classify("https://beta.example/issuer/y").unwrap();
        assert_eq!(p.name(), "beta");

        assert!(reg.classify("https://unknown.example/").is_none());
    }

    #[test]
    fn registry_rejects_duplicate_name() {
        let mut reg = FederationRegistry::new();
        reg.register(provider("alpha", "b-a-", "https://alpha.example/"))
            .unwrap();
        let err = reg
            .register(provider("alpha", "b-z-", "https://other.example/"))
            .unwrap_err();
        assert!(matches!(err, OidcError::FederationConflict(_)));
    }

    #[test]
    fn registry_rejects_duplicate_uid_prefix() {
        let mut reg = FederationRegistry::new();
        reg.register(provider("alpha", "b-a-", "https://alpha.example/"))
            .unwrap();
        let err = reg
            .register(provider("alpha2", "b-a-", "https://alpha2.example/"))
            .unwrap_err();
        assert!(matches!(err, OidcError::FederationConflict(_)));
    }

    #[test]
    fn synthetic_uid_concatenates_prefix_and_sanitized_scope() {
        let mut reg = FederationRegistry::new();
        reg.register(provider("alpha", "b-a-", "https://alpha.example/"))
            .unwrap();
        let uid = reg
            .synthetic_uid("https://alpha.example/issuer/x", "owner/repo")
            .unwrap();
        assert_eq!(uid, "b-a-owner-repo");
    }

    #[test]
    fn synthetic_uid_none_for_unknown_issuer() {
        let reg = FederationRegistry::new();
        assert!(reg
            .synthetic_uid("https://unknown.example/", "scope")
            .is_none());
    }

    #[test]
    fn sanitize_scope_collapses_unsafe_chars() {
        assert_eq!(sanitize_scope("owner/repo"), "owner-repo");
        assert_eq!(
            sanitize_scope("evil!owner/repo<script>"),
            "evil-owner-repo-script"
        );
        assert_eq!(sanitize_scope("hello"), "hello");
        assert_eq!(sanitize_scope("-trim-"), "trim");
    }

    #[test]
    fn peek_jwt_issuer_extracts_iss() {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#); // alg-pin-allow: peek-only test; signature never verified
        let payload = URL_SAFE_NO_PAD.encode(br#"{"iss":"https://alpha.example/","aud":"x"}"#);
        let sig = URL_SAFE_NO_PAD.encode(b"sig");
        let jwt = format!("{header}.{payload}.{sig}");
        let iss = peek_jwt_issuer(&jwt).unwrap();
        assert_eq!(iss, "https://alpha.example/");
    }

    #[test]
    fn peek_jwt_issuer_rejects_two_parts() {
        let err = peek_jwt_issuer("only.two").unwrap_err();
        assert!(matches!(err, OidcError::JwtValidation(_)));
    }

    #[test]
    fn peek_jwt_issuer_rejects_four_parts() {
        let err = peek_jwt_issuer("a.b.c.d").unwrap_err();
        assert!(matches!(err, OidcError::JwtValidation(_)));
    }

    #[test]
    fn peek_jwt_issuer_rejects_bad_base64() {
        let err = peek_jwt_issuer("h.!!notb64!!.s").unwrap_err();
        assert!(matches!(err, OidcError::JwtValidation(_)));
    }

    #[test]
    fn peek_jwt_issuer_rejects_missing_iss() {
        let no_iss = URL_SAFE_NO_PAD.encode(br#"{"aud":"x"}"#);
        let err = peek_jwt_issuer(&format!("h.{no_iss}.s")).unwrap_err();
        assert!(matches!(err, OidcError::JwtValidation(_)));
    }
}
