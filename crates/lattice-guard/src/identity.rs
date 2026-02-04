//! SPIFFE identity matching for policy selection.
//!
//! This module provides pattern matching for SPIFFE IDs, enabling
//! identity-based policy selection for AI agents in nucleus sandboxes.
//!
//! # SPIFFE ID Format
//!
//! SPIFFE IDs follow the format: `spiffe://<trust-domain>/<path>`
//!
//! Examples:
//! - `spiffe://nucleus.local/ns/default/sa/coder-001`
//! - `spiffe://nucleus.local/agent/architect/task-123`
//!
//! # Pattern Matching
//!
//! Patterns support glob-style matching:
//! - `*` matches any characters except `/`
//! - `**` matches any characters including `/`
//!
//! Examples:
//! - `spiffe://nucleus.local/ns/*/sa/coder-*` matches any coder in any namespace
//! - `spiffe://nucleus.local/agent/**` matches any agent path
//!
//! # Example
//!
//! ```
//! use lattice_guard::identity::{SpiffeIdMatcher, IdentityPolicy};
//! use lattice_guard::PermissionLattice;
//!
//! // Create a policy that matches coder agents
//! let policy = IdentityPolicy {
//!     pattern: "spiffe://nucleus.local/ns/*/sa/coder-*".to_string(),
//!     permissions: PermissionLattice::codegen(),
//! };
//!
//! // Check if a SPIFFE ID matches
//! let matcher = SpiffeIdMatcher::new(&policy.pattern);
//! assert!(matcher.matches("spiffe://nucleus.local/ns/default/sa/coder-001"));
//! assert!(!matcher.matches("spiffe://nucleus.local/ns/default/sa/reviewer-001"));
//! ```

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::PermissionLattice;

/// Pattern matcher for SPIFFE IDs.
///
/// Uses glob-style patterns to match SPIFFE identities.
#[derive(Debug, Clone)]
pub struct SpiffeIdMatcher {
    pattern: String,
    regex: regex::Regex,
}

impl SpiffeIdMatcher {
    /// Create a new SPIFFE ID matcher from a glob pattern.
    ///
    /// # Panics
    ///
    /// Panics if the pattern cannot be compiled into a regex.
    pub fn new(pattern: &str) -> Self {
        let regex = Self::glob_to_regex(pattern);
        Self {
            pattern: pattern.to_string(),
            regex: regex::Regex::new(&regex).expect("invalid SPIFFE pattern"),
        }
    }

    /// Try to create a new matcher, returning None if the pattern is invalid.
    pub fn try_new(pattern: &str) -> Option<Self> {
        let regex = Self::glob_to_regex(pattern);
        regex::Regex::new(&regex).ok().map(|r| Self {
            pattern: pattern.to_string(),
            regex: r,
        })
    }

    /// Check if a SPIFFE ID matches this pattern.
    pub fn matches(&self, spiffe_id: &str) -> bool {
        self.regex.is_match(spiffe_id)
    }

    /// Get the original pattern.
    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    /// Convert a glob pattern to a regex pattern.
    fn glob_to_regex(pattern: &str) -> String {
        let mut regex = String::with_capacity(pattern.len() * 2);
        regex.push('^');

        let mut chars = pattern.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '*' => {
                    if chars.peek() == Some(&'*') {
                        chars.next(); // consume second *
                                      // ** matches anything including /
                        regex.push_str(".*");
                    } else {
                        // Single * matches anything except /
                        regex.push_str("[^/]*");
                    }
                }
                '?' => regex.push_str("[^/]"),
                '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' | '\\' => {
                    regex.push('\\');
                    regex.push(c);
                }
                _ => regex.push(c),
            }
        }

        regex.push('$');
        regex
    }
}

/// A policy associated with a SPIFFE identity pattern.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IdentityPolicy {
    /// Glob pattern to match SPIFFE IDs.
    pub pattern: String,
    /// Permissions to apply when the pattern matches.
    pub permissions: PermissionLattice,
}

impl IdentityPolicy {
    /// Create a new identity policy.
    pub fn new(pattern: impl Into<String>, permissions: PermissionLattice) -> Self {
        Self {
            pattern: pattern.into(),
            permissions,
        }
    }

    /// Check if a SPIFFE ID matches this policy.
    pub fn matches(&self, spiffe_id: &str) -> bool {
        SpiffeIdMatcher::try_new(&self.pattern)
            .map(|m| m.matches(spiffe_id))
            .unwrap_or(false)
    }
}

/// A set of identity-based policies.
///
/// Policies are evaluated in order; the first matching policy is used.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IdentityPolicySet {
    /// Ordered list of policies. First match wins.
    pub policies: Vec<IdentityPolicy>,
    /// Default permissions when no policy matches.
    #[cfg_attr(feature = "serde", serde(default))]
    pub default_permissions: Option<PermissionLattice>,
}

impl IdentityPolicySet {
    /// Create a new empty policy set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a policy to the set.
    pub fn add_policy(&mut self, policy: IdentityPolicy) {
        self.policies.push(policy);
    }

    /// Set the default permissions for unmatched identities.
    pub fn with_default(mut self, permissions: PermissionLattice) -> Self {
        self.default_permissions = Some(permissions);
        self
    }

    /// Find the permissions for a given SPIFFE ID.
    ///
    /// Returns the permissions from the first matching policy, or the default
    /// permissions if no policy matches.
    pub fn permissions_for(&self, spiffe_id: &str) -> Option<&PermissionLattice> {
        for policy in &self.policies {
            if policy.matches(spiffe_id) {
                return Some(&policy.permissions);
            }
        }
        self.default_permissions.as_ref()
    }

    /// Check if a SPIFFE ID has any matching policy.
    pub fn has_policy_for(&self, spiffe_id: &str) -> bool {
        self.policies.iter().any(|p| p.matches(spiffe_id))
    }

    /// Get the matching policy for a SPIFFE ID, if any.
    pub fn matching_policy(&self, spiffe_id: &str) -> Option<&IdentityPolicy> {
        self.policies.iter().find(|p| p.matches(spiffe_id))
    }
}

/// Parse a SPIFFE ID into its components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSpiffeId {
    /// The trust domain (e.g., "nucleus.local").
    pub trust_domain: String,
    /// The path components (e.g., ["ns", "default", "sa", "coder-001"]).
    pub path: Vec<String>,
}

impl ParsedSpiffeId {
    /// Parse a SPIFFE ID string.
    ///
    /// Returns None if the string is not a valid SPIFFE ID.
    pub fn parse(spiffe_id: &str) -> Option<Self> {
        let stripped = spiffe_id.strip_prefix("spiffe://")?;
        let (trust_domain, path_str) = stripped.split_once('/')?;

        if trust_domain.is_empty() {
            return None;
        }

        let path: Vec<String> = path_str
            .split('/')
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();

        Some(Self {
            trust_domain: trust_domain.to_string(),
            path,
        })
    }

    /// Get the namespace if the path follows the standard format.
    ///
    /// Standard format: `/ns/<namespace>/sa/<service-account>`
    pub fn namespace(&self) -> Option<&str> {
        if self.path.len() >= 2 && self.path[0] == "ns" {
            Some(&self.path[1])
        } else {
            None
        }
    }

    /// Get the service account if the path follows the standard format.
    pub fn service_account(&self) -> Option<&str> {
        if self.path.len() >= 4 && self.path[0] == "ns" && self.path[2] == "sa" {
            Some(&self.path[3])
        } else {
            None
        }
    }
}

impl std::fmt::Display for ParsedSpiffeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "spiffe://{}/{}", self.trust_domain, self.path.join("/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spiffe_id_matcher_exact() {
        let matcher = SpiffeIdMatcher::new("spiffe://nucleus.local/ns/default/sa/coder");
        assert!(matcher.matches("spiffe://nucleus.local/ns/default/sa/coder"));
        assert!(!matcher.matches("spiffe://nucleus.local/ns/default/sa/coder-001"));
        assert!(!matcher.matches("spiffe://other.local/ns/default/sa/coder"));
    }

    #[test]
    fn test_spiffe_id_matcher_wildcard() {
        let matcher = SpiffeIdMatcher::new("spiffe://nucleus.local/ns/*/sa/coder-*");
        assert!(matcher.matches("spiffe://nucleus.local/ns/default/sa/coder-001"));
        assert!(matcher.matches("spiffe://nucleus.local/ns/production/sa/coder-abc"));
        assert!(!matcher.matches("spiffe://nucleus.local/ns/default/sa/reviewer-001"));
        assert!(!matcher.matches("spiffe://other.local/ns/default/sa/coder-001"));
    }

    #[test]
    fn test_spiffe_id_matcher_double_wildcard() {
        let matcher = SpiffeIdMatcher::new("spiffe://nucleus.local/agent/**");
        assert!(matcher.matches("spiffe://nucleus.local/agent/architect"));
        assert!(matcher.matches("spiffe://nucleus.local/agent/coder/task-123"));
        assert!(matcher.matches("spiffe://nucleus.local/agent/deep/nested/path"));
        assert!(!matcher.matches("spiffe://nucleus.local/ns/default/sa/coder"));
    }

    #[test]
    fn test_spiffe_id_matcher_any_trust_domain() {
        let matcher = SpiffeIdMatcher::new("spiffe://*/ns/default/sa/coder");
        assert!(matcher.matches("spiffe://nucleus.local/ns/default/sa/coder"));
        assert!(matcher.matches("spiffe://other.domain/ns/default/sa/coder"));
        assert!(!matcher.matches("spiffe://nucleus.local/ns/prod/sa/coder"));
    }

    #[test]
    fn test_identity_policy_set() {
        let mut policy_set = IdentityPolicySet::new();

        policy_set.add_policy(IdentityPolicy::new(
            "spiffe://nucleus.local/ns/*/sa/coder-*",
            PermissionLattice::codegen(),
        ));

        policy_set.add_policy(IdentityPolicy::new(
            "spiffe://nucleus.local/ns/*/sa/reviewer-*",
            PermissionLattice::pr_review(),
        ));

        // Coder should get codegen permissions
        let coder_perms =
            policy_set.permissions_for("spiffe://nucleus.local/ns/default/sa/coder-001");
        assert!(coder_perms.is_some());
        assert_eq!(
            coder_perms.unwrap().description,
            "Code generation permissions (network-isolated)"
        );

        // Reviewer should get pr_review permissions
        let reviewer_perms =
            policy_set.permissions_for("spiffe://nucleus.local/ns/default/sa/reviewer-001");
        assert!(reviewer_perms.is_some());
        assert_eq!(reviewer_perms.unwrap().description, "PR review permissions");

        // Unknown identity should return None
        let unknown_perms =
            policy_set.permissions_for("spiffe://nucleus.local/ns/default/sa/unknown");
        assert!(unknown_perms.is_none());
    }

    #[test]
    fn test_identity_policy_set_with_default() {
        let policy_set = IdentityPolicySet::new().with_default(PermissionLattice::restrictive());

        // Unknown identity should get default permissions
        let perms = policy_set.permissions_for("spiffe://nucleus.local/ns/default/sa/unknown");
        assert!(perms.is_some());
        assert_eq!(perms.unwrap().description, "Restrictive permissions");
    }

    #[test]
    fn test_parsed_spiffe_id() {
        let parsed =
            ParsedSpiffeId::parse("spiffe://nucleus.local/ns/default/sa/coder-001").unwrap();
        assert_eq!(parsed.trust_domain, "nucleus.local");
        assert_eq!(parsed.path, vec!["ns", "default", "sa", "coder-001"]);
        assert_eq!(parsed.namespace(), Some("default"));
        assert_eq!(parsed.service_account(), Some("coder-001"));
    }

    #[test]
    fn test_parsed_spiffe_id_non_standard() {
        let parsed =
            ParsedSpiffeId::parse("spiffe://nucleus.local/agent/architect/task-123").unwrap();
        assert_eq!(parsed.trust_domain, "nucleus.local");
        assert_eq!(parsed.path, vec!["agent", "architect", "task-123"]);
        assert_eq!(parsed.namespace(), None);
        assert_eq!(parsed.service_account(), None);
    }

    #[test]
    fn test_parsed_spiffe_id_invalid() {
        assert!(ParsedSpiffeId::parse("not-a-spiffe-id").is_none());
        assert!(ParsedSpiffeId::parse("spiffe://").is_none());
        assert!(ParsedSpiffeId::parse("spiffe:///path").is_none());
    }

    #[test]
    fn test_first_match_wins() {
        let mut policy_set = IdentityPolicySet::new();

        // More specific pattern first
        policy_set.add_policy(IdentityPolicy::new(
            "spiffe://nucleus.local/ns/production/sa/coder-*",
            PermissionLattice::restrictive(),
        ));

        // More general pattern second
        policy_set.add_policy(IdentityPolicy::new(
            "spiffe://nucleus.local/ns/*/sa/coder-*",
            PermissionLattice::permissive(),
        ));

        // Production coder should get restrictive (first match)
        let prod_perms =
            policy_set.permissions_for("spiffe://nucleus.local/ns/production/sa/coder-001");
        assert!(prod_perms.is_some());
        assert_eq!(prod_perms.unwrap().description, "Restrictive permissions");

        // Other namespace coder should get permissive (second match)
        let dev_perms =
            policy_set.permissions_for("spiffe://nucleus.local/ns/development/sa/coder-001");
        assert!(dev_perms.is_some());
        assert_eq!(dev_perms.unwrap().description, "Permissive permissions");
    }
}
