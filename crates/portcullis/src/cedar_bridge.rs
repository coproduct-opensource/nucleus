//! Cedar policy bridge — evaluate nucleus Operations against Cedar policies.
//!
//! Maps the nucleus permission model to Cedar's authorization model:
//!
//! ```text
//! Nucleus                    Cedar
//! ─────────                  ─────
//! agent session_id     →     principal  (Agent::"session-uuid")
//! Operation            →     action     (Action::"write_files")
//! subject (path/url)   →     resource   (Resource::"path/to/file")
//! IFC label            →     context    (integrity, authority, provenance)
//! ```
//!
//! Cedar policies are human-readable and analyzable:
//!
//! ```cedar
//! // Allow reads from any path
//! permit(
//!     principal is Agent,
//!     action == Action::"read_files",
//!     resource
//! );
//!
//! // Block writes when source has adversarial integrity
//! forbid(
//!     principal is Agent,
//!     action == Action::"write_files",
//!     resource
//! ) when {
//!     context.integrity == "adversarial"
//! };
//!
//! // Allow web_fetch but only to approved domains
//! permit(
//!     principal is Agent,
//!     action == Action::"web_fetch",
//!     resource
//! ) when {
//!     resource.domain in ["crates.io", "docs.rs", "github.com"]
//! };
//! ```
//!
//! The Cedar evaluator runs AFTER the portcullis lattice check — it's an
//! additional policy layer, not a replacement. The lattice provides formal
//! monotonicity guarantees; Cedar provides human-readable, auditable rules.

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request, Response,
};
use portcullis_core::{AuthorityLevel, ConfLevel, IntegLevel, Operation};

/// A Cedar policy evaluator for nucleus operations.
pub struct CedarEvaluator {
    policies: PolicySet,
    authorizer: Authorizer,
}

/// Result of a Cedar policy evaluation.
#[derive(Debug)]
pub struct CedarResult {
    /// Cedar's decision (Allow or Deny).
    pub decision: Decision,
    /// Human-readable explanation of why.
    pub reasons: Vec<String>,
}

impl CedarEvaluator {
    /// Create a new evaluator from Cedar policy source.
    ///
    /// Returns an error if the policies fail to parse.
    pub fn new(policy_src: &str) -> Result<Self, String> {
        let policies: PolicySet = policy_src
            .parse()
            .map_err(|e| format!("Cedar policy parse error: {e}"))?;
        Ok(Self {
            policies,
            authorizer: Authorizer::new(),
        })
    }

    /// Evaluate a nucleus operation against Cedar policies.
    ///
    /// Maps the operation to a Cedar request with:
    /// - principal: `Agent::"<session_id>"`
    /// - action: `Action::"<operation_name>"`
    /// - resource: `Resource::"<subject>"`
    /// - context: IFC label dimensions (integrity, authority, confidentiality)
    pub fn evaluate(
        &self,
        session_id: &str,
        operation: Operation,
        subject: &str,
        integrity: IntegLevel,
        authority: AuthorityLevel,
        confidentiality: ConfLevel,
    ) -> CedarResult {
        let principal: EntityUid = format!("Agent::\"{}\"", session_id)
            .parse()
            .unwrap_or_else(|_| "Agent::\"unknown\"".parse().unwrap());
        let action: EntityUid = format!("Action::\"{}\"", operation)
            .parse()
            .unwrap_or_else(|_| "Action::\"unknown\"".parse().unwrap());
        let resource: EntityUid = format!("Resource::\"{}\"", subject)
            .parse()
            .unwrap_or_else(|_| "Resource::\"unknown\"".parse().unwrap());

        let context_json = serde_json::json!({
            "integrity": format!("{:?}", integrity).to_lowercase(),
            "authority": format!("{:?}", authority).to_lowercase(),
            "confidentiality": format!("{:?}", confidentiality).to_lowercase(),
            "operation": operation.to_string(),
            "subject": subject,
        });

        let context =
            Context::from_json_value(context_json, None).unwrap_or_else(|_| Context::empty());

        let request =
            Request::new(principal, action, resource, context, None).unwrap_or_else(|_| {
                // Fallback: empty request that will be denied by default
                Request::new(
                    "Agent::\"fallback\"".parse().unwrap(),
                    "Action::\"unknown\"".parse().unwrap(),
                    "Resource::\"unknown\"".parse().unwrap(),
                    Context::empty(),
                    None,
                )
                .unwrap()
            });

        let entities = Entities::empty();
        let response: Response = self
            .authorizer
            .is_authorized(&request, &self.policies, &entities);

        let reasons: Vec<String> = response
            .diagnostics()
            .reason()
            .map(|id| id.to_string())
            .collect();

        CedarResult {
            decision: response.decision(),
            reasons,
        }
    }

    /// Check if an operation is allowed by Cedar policies.
    pub fn is_allowed(
        &self,
        session_id: &str,
        operation: Operation,
        subject: &str,
        integrity: IntegLevel,
        authority: AuthorityLevel,
        confidentiality: ConfLevel,
    ) -> bool {
        self.evaluate(
            session_id,
            operation,
            subject,
            integrity,
            authority,
            confidentiality,
        )
        .decision
            == Decision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASIC_POLICY: &str = r#"
permit(
    principal,
    action == Action::"read_files",
    resource
);

forbid(
    principal,
    action == Action::"write_files",
    resource
) when {
    context.integrity == "adversarial"
};

permit(
    principal,
    action == Action::"write_files",
    resource
) when {
    context.integrity == "trusted"
};
"#;

    #[test]
    fn read_always_allowed() {
        let eval = CedarEvaluator::new(BASIC_POLICY).unwrap();
        assert!(eval.is_allowed(
            "test-session",
            Operation::ReadFiles,
            "/workspace/main.rs",
            IntegLevel::Adversarial,
            AuthorityLevel::NoAuthority,
            ConfLevel::Public,
        ));
    }

    #[test]
    fn write_denied_when_adversarial() {
        let eval = CedarEvaluator::new(BASIC_POLICY).unwrap();
        assert!(!eval.is_allowed(
            "test-session",
            Operation::WriteFiles,
            "/workspace/output.rs",
            IntegLevel::Adversarial,
            AuthorityLevel::NoAuthority,
            ConfLevel::Public,
        ));
    }

    #[test]
    fn write_allowed_when_trusted() {
        let eval = CedarEvaluator::new(BASIC_POLICY).unwrap();
        assert!(eval.is_allowed(
            "test-session",
            Operation::WriteFiles,
            "/workspace/output.rs",
            IntegLevel::Trusted,
            AuthorityLevel::Directive,
            ConfLevel::Internal,
        ));
    }

    #[test]
    fn invalid_policy_returns_error() {
        let result = CedarEvaluator::new("this is not valid cedar");
        assert!(result.is_err());
    }
}
