//! Federation rule registry + audience-matcher (task #41).
//!
//! A declarative `(subject_prefix, audience, allowed_grants,
//! max_token_lifetime)` rule store loaded from a TOML file at startup
//! and hot-reloadable in-process. Decisions are total: every
//! `(subject, audience, grant)` triple resolves to either `Allow` or
//! `Deny` (with a structured reason that audit logs reflect).
//!
//! # Threat model alignment
//!
//! - `THREAT_MODEL.md` T05 (federation-rule misconfiguration) is the
//!   dominant operational failure mode for OIDC federation. The
//!   mitigations baked into this module:
//!   1. **Default-deny.** No matching rule → `Deny(NoMatchingRule)`.
//!   2. **`deny_unknown_fields`** on every wire type so typos in a
//!      production deploy fail loud rather than silently being ignored.
//!   3. **Glob restricted to `*` suffix on `subject_prefix`.** No full
//!      regex (defends ReDoS + accidental over-permissive patterns).
//!   4. **Bounded rule count** (`MAX_RULES = 1024`) prevents
//!      config-driven memory/CPU DoS.
//!   5. **Audit-log on every Deny** with the matched-rule-id (or
//!      `"no_match"`) so reviewers can diff configs against logs.
//!   6. **Atomic hot-reload via `Arc` swap**: in-flight handlers hold
//!      the snapshot they cloned at request entry; reload swaps the
//!      next snapshot without disrupting current evaluations.

use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Hard cap on the number of rules a single config can declare.
/// Anything larger is rejected at load — prevents both config-driven
/// memory bloat and pathological linear-scan cost.
pub const MAX_RULES: usize = 1024;

/// One federation rule. Matching semantics:
/// - `subject_prefix`: literal exact match OR (if it ends with `*`)
///   prefix match on the substring before the `*`. NO regex.
/// - `audience`: literal exact match.
/// - `allowed_grants`: the requested grant URI must be a member.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FederationRule {
    /// Stable identifier used in audit logs.
    pub id: String,
    /// Subject SPIFFE-ID prefix, with optional `*` suffix for wildcard.
    pub subject_prefix: String,
    /// Audience URL the issued token will be bound to. Exact match.
    pub audience: String,
    /// Grant URIs this rule permits (e.g. RFC 8693 token-exchange URN).
    pub allowed_grants: Vec<String>,
    /// Upper bound on the issued token's lifetime. The token endpoint
    /// clamps to `min(this, OP-global-cap, subject_token_exp - now)`.
    pub max_token_lifetime_secs: u64,
}

/// The on-disk + in-memory rules document. Wrapper so the TOML root
/// is a table with a `rule` array (idiomatic TOML).
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FederationRules {
    #[serde(default)]
    pub rule: Vec<FederationRule>,
}

impl FederationRules {
    /// Parse a TOML string. Rejects > `MAX_RULES` rules.
    pub fn parse_toml(s: &str) -> Result<Self, FederationError> {
        let rules: FederationRules = toml::from_str(s)?;
        if rules.rule.len() > MAX_RULES {
            return Err(FederationError::TooManyRules {
                got: rules.rule.len(),
                max: MAX_RULES,
            });
        }
        for rule in &rules.rule {
            if rule.id.trim().is_empty() {
                return Err(FederationError::InvalidRule(
                    "rule.id must be non-empty".to_string(),
                ));
            }
            if rule.subject_prefix.matches('*').count() > 1 {
                return Err(FederationError::InvalidRule(format!(
                    "rule {:?}: subject_prefix may contain at most one `*` (only as final char)",
                    rule.id
                )));
            }
            if rule.subject_prefix.contains('*') && !rule.subject_prefix.ends_with('*') {
                return Err(FederationError::InvalidRule(format!(
                    "rule {:?}: `*` must be the FINAL character of subject_prefix \
                     (no regex semantics)",
                    rule.id
                )));
            }
            // (#55 HIGH-4) Reject unanchored wildcards: the literal-prefix
            // portion (everything before the trailing `*`) MUST start with
            // `spiffe://` and contain a path-separator after the authority.
            // A bare `"*"` or `"spiffe://"` alone would otherwise allow
            // any subject — one typo turns into global-allow.
            let literal_prefix = rule.subject_prefix.trim_end_matches('*');
            if !literal_prefix.starts_with("spiffe://") {
                return Err(FederationError::InvalidRule(format!(
                    "rule {:?}: subject_prefix must start with `spiffe://`, got {:?}",
                    rule.id, rule.subject_prefix
                )));
            }
            let after_scheme = &literal_prefix["spiffe://".len()..];
            if !after_scheme.contains('/') {
                return Err(FederationError::InvalidRule(format!(
                    "rule {:?}: subject_prefix must include a trust-domain \
                     authority + path-separator (e.g. \"spiffe://td/*\"), got {:?}",
                    rule.id, rule.subject_prefix
                )));
            }
            if rule.audience.trim().is_empty() {
                return Err(FederationError::InvalidRule(format!(
                    "rule {:?}: audience must be non-empty",
                    rule.id
                )));
            }
            if rule.allowed_grants.is_empty() {
                return Err(FederationError::InvalidRule(format!(
                    "rule {:?}: allowed_grants must list at least one grant URI",
                    rule.id
                )));
            }
        }
        Ok(rules)
    }

    /// Read + parse from a TOML file.
    pub fn read_from_file(path: impl AsRef<Path>) -> Result<Self, FederationError> {
        let path = path.as_ref();
        let s = std::fs::read_to_string(path)
            .map_err(|e| FederationError::Io(format!("read {path:?}: {e}")))?;
        Self::parse_toml(&s)
    }
}

#[derive(Debug, Error)]
pub enum FederationError {
    #[error("federation rules TOML parse: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("federation rule invalid: {0}")]
    InvalidRule(String),
    #[error("too many rules: {got} declared, max {max}")]
    TooManyRules { got: usize, max: usize },
    #[error("federation rules io: {0}")]
    Io(String),
}

/// Outcome of a `(subject, audience, grant)` evaluation.
#[derive(Debug, Clone)]
pub enum Decision {
    Allow {
        matched_rule_id: String,
        max_lifetime: Duration,
    },
    Deny(DenyReason),
}

/// Structured Deny reason — surfaces in audit logs.
#[derive(Debug, Clone)]
pub enum DenyReason {
    /// No rule matched both `(subject, audience)`.
    NoMatchingRule,
    /// A rule matched `(subject, audience)` but didn't list the requested grant.
    GrantNotAllowed {
        rule_id: String,
        requested: String,
        allowed: Vec<String>,
    },
}

/// Holds the current rules behind an atomic `Arc` swap so hot-reload
/// preserves in-flight evaluations.
pub struct FederationRegistry {
    inner: RwLock<Arc<FederationRules>>,
}

impl FederationRegistry {
    pub fn new(initial: FederationRules) -> Self {
        Self {
            inner: RwLock::new(Arc::new(initial)),
        }
    }

    /// Empty registry — every evaluation returns `Deny(NoMatchingRule)`.
    /// Useful for tests; production should bootstrap from a TOML file.
    pub fn empty() -> Self {
        Self::new(FederationRules::default())
    }

    /// Snapshot the current rules. Callers hold this `Arc` for the
    /// lifetime of their request; a concurrent `reload` swaps the
    /// next snapshot without affecting outstanding ones.
    pub fn snapshot(&self) -> Arc<FederationRules> {
        let guard = self
            .inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Arc::clone(&guard)
    }

    /// Atomically replace the active rule set. Returns the count of
    /// rules in the new snapshot for audit-log emission at the call
    /// site.
    pub fn reload(&self, next: FederationRules) -> usize {
        let count = next.rule.len();
        let mut guard = self
            .inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Arc::new(next);
        count
    }

    /// Convenience: reload from a TOML file.
    pub fn reload_from_file(&self, path: impl AsRef<Path>) -> Result<usize, FederationError> {
        let next = FederationRules::read_from_file(path)?;
        Ok(self.reload(next))
    }

    /// Evaluate a `(subject, audience, grant)` triple. The result is
    /// **total** — every input maps to `Allow` or `Deny`.
    ///
    /// Matching:
    /// 1. First rule whose `subject_prefix` matches the subject AND
    ///    whose `audience` equals `audience` is selected.
    /// 2. If the selected rule's `allowed_grants` contains `grant` →
    ///    `Allow` with the rule's lifetime cap.
    /// 3. Selected rule but grant not in allowed list → `Deny(GrantNotAllowed)`.
    /// 4. No rule matched → `Deny(NoMatchingRule)`.
    ///
    /// (#55 MED-7) Audience matching is **byte-exact, case-sensitive**.
    /// RFC 3986 declares scheme + host case-insensitive, but operators
    /// who write `https://RP.example/api` will see a Deny for workload
    /// requests of `https://rp.example/api`. This trades operator
    /// confusion for predictability + audit-log clarity (no implicit
    /// normalization). Documented in operator runbook §3; pinned by
    /// test `evaluate_audience_match_is_case_sensitive`.
    pub fn evaluate(&self, subject: &str, audience: &str, grant: &str) -> Decision {
        let rules = self.snapshot();
        for rule in &rules.rule {
            if !subject_matches(&rule.subject_prefix, subject) {
                continue;
            }
            if rule.audience != audience {
                continue;
            }
            if rule.allowed_grants.iter().any(|g| g == grant) {
                return Decision::Allow {
                    matched_rule_id: rule.id.clone(),
                    max_lifetime: Duration::from_secs(rule.max_token_lifetime_secs),
                };
            } else {
                return Decision::Deny(DenyReason::GrantNotAllowed {
                    rule_id: rule.id.clone(),
                    requested: grant.to_string(),
                    allowed: rule.allowed_grants.clone(),
                });
            }
        }
        Decision::Deny(DenyReason::NoMatchingRule)
    }

    /// Current rule count — for /healthz reporting.
    pub fn rule_count(&self) -> usize {
        self.snapshot().rule.len()
    }
}

impl Default for FederationRegistry {
    fn default() -> Self {
        Self::empty()
    }
}

fn subject_matches(prefix_pattern: &str, subject: &str) -> bool {
    if let Some(prefix) = prefix_pattern.strip_suffix('*') {
        subject.starts_with(prefix)
    } else {
        prefix_pattern == subject
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GRANT_TX: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

    fn rule(
        id: &str,
        subject_prefix: &str,
        audience: &str,
        allowed_grants: &[&str],
        max_lifetime_secs: u64,
    ) -> FederationRule {
        FederationRule {
            id: id.to_string(),
            subject_prefix: subject_prefix.to_string(),
            audience: audience.to_string(),
            allowed_grants: allowed_grants.iter().map(|s| s.to_string()).collect(),
            max_token_lifetime_secs: max_lifetime_secs,
        }
    }

    #[test]
    fn empty_registry_denies_everything() {
        let reg = FederationRegistry::empty();
        let d = reg.evaluate("spiffe://x/y", "https://rp/", GRANT_TX);
        assert!(matches!(d, Decision::Deny(DenyReason::NoMatchingRule)));
    }

    #[test]
    fn exact_subject_match_allows() {
        let reg = FederationRegistry::new(FederationRules {
            rule: vec![rule(
                "r1",
                "spiffe://prod/ns/agents/sa/coder",
                "https://rp/api",
                &[GRANT_TX],
                3600,
            )],
        });
        let d = reg.evaluate(
            "spiffe://prod/ns/agents/sa/coder",
            "https://rp/api",
            GRANT_TX,
        );
        match d {
            Decision::Allow {
                matched_rule_id,
                max_lifetime,
            } => {
                assert_eq!(matched_rule_id, "r1");
                assert_eq!(max_lifetime, Duration::from_secs(3600));
            }
            _ => panic!("expected Allow"),
        }
    }

    /// (#55 MED-7) Pin the audience case-sensitivity decision: matching
    /// is byte-exact with no implicit lowercase normalization. Operators
    /// MUST write the audience in the same case the workload requests.
    #[test]
    fn evaluate_audience_match_is_case_sensitive() {
        let reg = FederationRegistry::new(FederationRules {
            rule: vec![rule(
                "r-strict",
                "spiffe://prod/ns/agents/sa/coder",
                "https://RP.example/api", // mixed-case host
                &[GRANT_TX],
                300,
            )],
        });
        // Exact-case match succeeds.
        let d = reg.evaluate(
            "spiffe://prod/ns/agents/sa/coder",
            "https://RP.example/api",
            GRANT_TX,
        );
        assert!(matches!(d, Decision::Allow { .. }));

        // RFC 3986 would consider these equivalent, but we treat them
        // as distinct. NoMatchingRule, not GrantNotAllowed.
        let d = reg.evaluate(
            "spiffe://prod/ns/agents/sa/coder",
            "https://rp.example/api", // lowercase host
            GRANT_TX,
        );
        assert!(matches!(d, Decision::Deny(DenyReason::NoMatchingRule)));
    }

    #[test]
    fn wildcard_suffix_prefix_match_allows() {
        let reg = FederationRegistry::new(FederationRules {
            rule: vec![rule(
                "wild",
                "spiffe://prod/ns/agents/*",
                "https://rp/api",
                &[GRANT_TX],
                300,
            )],
        });
        let d = reg.evaluate(
            "spiffe://prod/ns/agents/sa/anything",
            "https://rp/api",
            GRANT_TX,
        );
        assert!(matches!(d, Decision::Allow { .. }));
    }

    #[test]
    fn wildcard_does_not_match_outside_prefix() {
        let reg = FederationRegistry::new(FederationRules {
            rule: vec![rule(
                "wild",
                "spiffe://prod/ns/agents/*",
                "https://rp/api",
                &[GRANT_TX],
                300,
            )],
        });
        let d = reg.evaluate("spiffe://prod/ns/other/sa/x", "https://rp/api", GRANT_TX);
        assert!(matches!(d, Decision::Deny(DenyReason::NoMatchingRule)));
    }

    #[test]
    fn wrong_audience_denies_no_match() {
        let reg = FederationRegistry::new(FederationRules {
            rule: vec![rule(
                "r1",
                "spiffe://prod/ns/agents/sa/coder",
                "https://rp/api",
                &[GRANT_TX],
                300,
            )],
        });
        let d = reg.evaluate(
            "spiffe://prod/ns/agents/sa/coder",
            "https://other-rp/api",
            GRANT_TX,
        );
        assert!(matches!(d, Decision::Deny(DenyReason::NoMatchingRule)));
    }

    #[test]
    fn matched_rule_with_wrong_grant_returns_grant_not_allowed() {
        let reg = FederationRegistry::new(FederationRules {
            rule: vec![rule(
                "r1",
                "spiffe://prod/ns/agents/sa/coder",
                "https://rp/api",
                &[GRANT_TX],
                300,
            )],
        });
        let d = reg.evaluate(
            "spiffe://prod/ns/agents/sa/coder",
            "https://rp/api",
            "authorization_code",
        );
        match d {
            Decision::Deny(DenyReason::GrantNotAllowed {
                rule_id,
                requested,
                allowed,
            }) => {
                assert_eq!(rule_id, "r1");
                assert_eq!(requested, "authorization_code");
                assert_eq!(allowed, vec![GRANT_TX.to_string()]);
            }
            _ => panic!("expected GrantNotAllowed"),
        }
    }

    #[test]
    fn first_matching_rule_wins() {
        let reg = FederationRegistry::new(FederationRules {
            rule: vec![
                rule(
                    "narrow",
                    "spiffe://prod/ns/agents/sa/coder",
                    "https://rp/api",
                    &[GRANT_TX],
                    600,
                ),
                rule(
                    "wide",
                    "spiffe://prod/*",
                    "https://rp/api",
                    &[GRANT_TX],
                    300,
                ),
            ],
        });
        let d = reg.evaluate(
            "spiffe://prod/ns/agents/sa/coder",
            "https://rp/api",
            GRANT_TX,
        );
        match d {
            Decision::Allow {
                matched_rule_id, ..
            } => assert_eq!(matched_rule_id, "narrow"),
            _ => panic!("expected Allow"),
        }
    }

    #[test]
    fn toml_round_trip_parses() {
        let s = r#"
        [[rule]]
        id = "test"
        subject_prefix = "spiffe://prod/ns/agents/*"
        audience = "https://rp.example/api"
        allowed_grants = ["urn:ietf:params:oauth:grant-type:token-exchange"]
        max_token_lifetime_secs = 1800
        "#;
        let rules = FederationRules::parse_toml(s).unwrap();
        assert_eq!(rules.rule.len(), 1);
        assert_eq!(rules.rule[0].id, "test");
        assert_eq!(rules.rule[0].max_token_lifetime_secs, 1800);
    }

    #[test]
    fn toml_rejects_unknown_field() {
        // Typo `audiance` (instead of `audience`) — must fail-loud.
        let s = r#"
        [[rule]]
        id = "test"
        subject_prefix = "spiffe://prod/*"
        audiance = "https://rp.example/api"
        allowed_grants = ["urn:ietf:params:oauth:grant-type:token-exchange"]
        max_token_lifetime_secs = 1800
        "#;
        let err = FederationRules::parse_toml(s).unwrap_err();
        assert!(matches!(err, FederationError::Toml(_)));
    }

    #[test]
    fn toml_rejects_regex_chars_in_subject_prefix() {
        // Disallowed: `*` anywhere but the final position.
        let s = r#"
        [[rule]]
        id = "regex-attempt"
        subject_prefix = "spiffe://*/ns/agents/*"
        audience = "https://rp.example/api"
        allowed_grants = ["urn:ietf:params:oauth:grant-type:token-exchange"]
        max_token_lifetime_secs = 1800
        "#;
        let err = FederationRules::parse_toml(s).unwrap_err();
        assert!(matches!(err, FederationError::InvalidRule(_)));
    }

    #[test]
    fn toml_rejects_empty_audience() {
        let s = r#"
        [[rule]]
        id = "no-aud"
        subject_prefix = "spiffe://prod/*"
        audience = ""
        allowed_grants = ["urn:ietf:params:oauth:grant-type:token-exchange"]
        max_token_lifetime_secs = 1800
        "#;
        let err = FederationRules::parse_toml(s).unwrap_err();
        assert!(matches!(err, FederationError::InvalidRule(_)));
    }

    #[test]
    fn toml_rejects_empty_allowed_grants() {
        let s = r#"
        [[rule]]
        id = "no-grant"
        subject_prefix = "spiffe://prod/*"
        audience = "https://rp.example/api"
        allowed_grants = []
        max_token_lifetime_secs = 1800
        "#;
        let err = FederationRules::parse_toml(s).unwrap_err();
        assert!(matches!(err, FederationError::InvalidRule(_)));
    }

    #[test]
    fn toml_rejects_too_many_rules() {
        let mut s = String::new();
        for i in 0..(MAX_RULES + 1) {
            s.push_str(&format!(
                "[[rule]]\nid = \"r{i}\"\nsubject_prefix = \"spiffe://x/*\"\n\
                 audience = \"https://rp/\"\nallowed_grants = [\"{GRANT_TX}\"]\n\
                 max_token_lifetime_secs = 300\n"
            ));
        }
        let err = FederationRules::parse_toml(&s).unwrap_err();
        assert!(matches!(err, FederationError::TooManyRules { .. }));
    }

    #[test]
    fn reload_atomically_swaps_rules() {
        let reg = FederationRegistry::empty();
        // Initially: deny.
        let d = reg.evaluate("spiffe://x/y", "https://rp/", GRANT_TX);
        assert!(matches!(d, Decision::Deny(_)));

        // Reload: one allow rule.
        let next = FederationRules {
            rule: vec![rule("r1", "spiffe://x/*", "https://rp/", &[GRANT_TX], 300)],
        };
        let count = reg.reload(next);
        assert_eq!(count, 1);

        // Now allows.
        let d = reg.evaluate("spiffe://x/y", "https://rp/", GRANT_TX);
        assert!(matches!(d, Decision::Allow { .. }));
    }

    /// In-flight snapshot must survive a concurrent reload — captures
    /// the semantics that hot-reload doesn't disrupt outstanding evals.
    #[test]
    fn snapshot_taken_before_reload_keeps_old_rules() {
        let reg = FederationRegistry::new(FederationRules {
            rule: vec![rule("old", "spiffe://*", "https://rp/", &[GRANT_TX], 300)],
        });

        // Take snapshot — this is what an in-flight request would hold.
        let snap = reg.snapshot();

        // Reload to a different rule set.
        reg.reload(FederationRules {
            rule: vec![rule("new", "spiffe://*", "https://rp/", &[GRANT_TX], 999)],
        });

        // The snapshot still sees the old rule.
        assert_eq!(snap.rule[0].id, "old");
        assert_eq!(snap.rule[0].max_token_lifetime_secs, 300);

        // A fresh evaluation sees the new rule.
        let new_snap = reg.snapshot();
        assert_eq!(new_snap.rule[0].id, "new");
    }

    #[test]
    fn rule_count_observability() {
        let reg = FederationRegistry::empty();
        assert_eq!(reg.rule_count(), 0);
        reg.reload(FederationRules {
            rule: vec![rule("a", "spiffe://*", "https://rp/", &[GRANT_TX], 300)],
        });
        assert_eq!(reg.rule_count(), 1);
    }
}
