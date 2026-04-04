//! AgentMessagePolicy — policy kernel for inter-agent message exchange.
//!
//! Agent-to-agent communication (MCP tool calls, A2A message passing) is a
//! policy surface that is distinct from single-agent capability control.
//! A message leaving one agent boundary may carry:
//!
//! - Oversized payloads that violate the downstream agent's limits
//! - Secret or confidential data that should not cross the boundary
//! - AI-derived or opaque-external content requiring special handling
//! - Adversarially tainted payloads that require human approval
//!
//! This module provides a **pure, no-I/O** policy evaluator for outbound
//! agent messages. No transport is implemented here — this is the decision
//! kernel that MCP/A2A integrations can call before sending.
//!
//! ## Example
//!
//! ```rust
//! use portcullis_core::agent_message::{AgentMessagePolicy, MessageContext};
//! use portcullis_core::{ConfLevel, DerivationClass, IntegLevel};
//! use portcullis_core::combinators::CheckResult;
//!
//! let policy = AgentMessagePolicy {
//!     max_bytes: 4096,
//!     allow_secret: false,
//!     require_approval_for_untrusted: true,
//! };
//!
//! // Oversized message → Deny
//! let oversized = MessageContext {
//!     payload_bytes: 8192,
//!     conf_level: ConfLevel::Public,
//!     integ_level: IntegLevel::Trusted,
//!     derivation: DerivationClass::Deterministic,
//!     destination: "agent-b".into(),
//! };
//! assert!(policy.evaluate(&oversized).is_deny());
//!
//! // Secret message when allow_secret=false → Deny
//! let secret = MessageContext {
//!     payload_bytes: 100,
//!     conf_level: ConfLevel::Secret,
//!     integ_level: IntegLevel::Trusted,
//!     derivation: DerivationClass::Deterministic,
//!     destination: "agent-b".into(),
//! };
//! assert!(policy.evaluate(&secret).is_deny());
//!
//! // Untrusted message with require_approval_for_untrusted=true → RequiresApproval
//! let untrusted = MessageContext {
//!     payload_bytes: 100,
//!     conf_level: ConfLevel::Public,
//!     integ_level: IntegLevel::Adversarial,
//!     derivation: DerivationClass::OpaqueExternal,
//!     destination: "agent-b".into(),
//! };
//! assert!(policy.evaluate(&untrusted).is_requires_approval());
//! ```

use crate::combinators::CheckResult;
use crate::{ConfLevel, DerivationClass, IntegLevel};

// ═══════════════════════════════════════════════════════════════════════════
// MessageContext
// ═══════════════════════════════════════════════════════════════════════════

/// Context for a single outbound inter-agent message.
///
/// Passed to [`AgentMessagePolicy::evaluate`].
#[derive(Debug, Clone)]
pub struct MessageContext {
    /// Size of the message payload in bytes.
    pub payload_bytes: usize,
    /// Aggregated confidentiality label of the message content.
    pub conf_level: ConfLevel,
    /// Aggregated integrity label of the message content.
    ///
    /// Joins across all contributing data sources. Adversarial origin
    /// means at least one source was adversarially controlled.
    pub integ_level: IntegLevel,
    /// Derivation class of the message content.
    ///
    /// Joins across all contributing transforms. AI-derived content
    /// is non-reproducible; opaque-external has unknown provenance.
    pub derivation: DerivationClass,
    /// Opaque identifier for the destination agent or endpoint.
    ///
    /// Used for audit logging; not used in policy decisions by default.
    pub destination: String,
}

impl MessageContext {
    /// Whether the message carries adversarially controlled data.
    pub fn is_adversarial(&self) -> bool {
        self.integ_level == IntegLevel::Adversarial
    }

    /// Whether the message carries untrusted (but not adversarial) data.
    pub fn is_untrusted(&self) -> bool {
        self.integ_level < IntegLevel::Trusted
    }

    /// Whether the message carries secret data.
    pub fn is_secret(&self) -> bool {
        self.conf_level == ConfLevel::Secret
    }

    /// Whether the message content has non-deterministic provenance.
    pub fn is_nondeterministic(&self) -> bool {
        !matches!(self.derivation, DerivationClass::Deterministic)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// AgentMessagePolicy
// ═══════════════════════════════════════════════════════════════════════════

/// Policy kernel for outbound inter-agent messages.
///
/// Pure evaluator — no I/O, no side effects. Call [`evaluate`] before
/// actually sending a message. The result is a [`CheckResult`] from the
/// standard combinator surface so it composes with existing pipelines.
///
/// See module documentation for examples.
#[derive(Debug, Clone)]
pub struct AgentMessagePolicy {
    /// Maximum allowed payload bytes. Messages exceeding this are denied.
    pub max_bytes: usize,
    /// Whether `Secret` confidentiality data may cross the boundary.
    ///
    /// When `false`, any message with `conf_level == Secret` is denied.
    pub allow_secret: bool,
    /// Whether adversarial or opaque-external derivations require human approval.
    ///
    /// When `true`, messages with `integ_level < Trusted` or
    /// `derivation == OpaqueExternal` are escalated to `RequiresApproval`.
    pub require_approval_for_untrusted: bool,
}

impl AgentMessagePolicy {
    /// Permissive defaults: large limit, no secret restriction, no approval gate.
    pub fn permissive() -> Self {
        Self {
            max_bytes: usize::MAX,
            allow_secret: true,
            require_approval_for_untrusted: false,
        }
    }

    /// Strict defaults: 4 KiB limit, no secrets allowed, approval for untrusted.
    pub fn strict() -> Self {
        Self {
            max_bytes: 4096,
            allow_secret: false,
            require_approval_for_untrusted: true,
        }
    }

    /// Evaluate the policy against a message context.
    ///
    /// Evaluation order (first match wins):
    /// 1. Oversized → `Deny`
    /// 2. Secret when not allowed → `Deny`
    /// 3. Adversarial → `Deny` (stronger than untrusted, always blocked)
    /// 4. Untrusted/opaque derivation when `require_approval_for_untrusted` → `RequiresApproval`
    /// 5. Otherwise → `Allow`
    pub fn evaluate(&self, ctx: &MessageContext) -> CheckResult {
        // 1. Size gate — hard deny
        if ctx.payload_bytes > self.max_bytes {
            return CheckResult::Deny(format!(
                "agent-message: payload {} bytes exceeds limit of {} bytes (destination: {})",
                ctx.payload_bytes, self.max_bytes, ctx.destination
            ));
        }

        // 2. Confidentiality gate — hard deny
        if !self.allow_secret && ctx.is_secret() {
            return CheckResult::Deny(format!(
                "agent-message: Secret-labeled content may not cross boundary \
                 to '{}' — policy disallows secret exfiltration",
                ctx.destination
            ));
        }

        // 3. Adversarial integrity — hard deny regardless of approval gate
        if ctx.is_adversarial() {
            return CheckResult::Deny(format!(
                "agent-message: adversarially tainted payload blocked from '{}' \
                 — adversarial data must not cross agent boundaries without explicit \
                 declassification",
                ctx.destination
            ));
        }

        // 4. Untrusted / opaque-external derivation — require approval
        if self.require_approval_for_untrusted {
            if ctx.is_untrusted() {
                return CheckResult::RequiresApproval(format!(
                    "agent-message: untrusted integrity ({:?}) requires human \
                     approval before forwarding to '{}'",
                    ctx.integ_level, ctx.destination
                ));
            }
            if ctx.derivation == DerivationClass::OpaqueExternal {
                return CheckResult::RequiresApproval(format!(
                    "agent-message: opaque-external derivation requires human \
                     approval before forwarding to '{}'",
                    ctx.destination
                ));
            }
        }

        CheckResult::Allow
    }

    /// Build an audit log line for a message evaluation result.
    ///
    /// Includes the policy decision, destination, and key labels.
    pub fn audit_line(&self, ctx: &MessageContext, result: &CheckResult) -> String {
        let verdict = match result {
            CheckResult::Allow => "ALLOW",
            CheckResult::Deny(_) => "DENY",
            CheckResult::RequiresApproval(_) => "REQUIRES_APPROVAL",
            CheckResult::Abstain => "ABSTAIN",
        };
        format!(
            "agent_msg_policy verdict={verdict} dest={} bytes={} conf={:?} \
             integ={:?} deriv={:?}",
            ctx.destination, ctx.payload_bytes, ctx.conf_level, ctx.integ_level, ctx.derivation,
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(
        bytes: usize,
        conf: ConfLevel,
        integ: IntegLevel,
        deriv: DerivationClass,
    ) -> MessageContext {
        MessageContext {
            payload_bytes: bytes,
            conf_level: conf,
            integ_level: integ,
            derivation: deriv,
            destination: "agent-b".into(),
        }
    }

    fn clean(bytes: usize) -> MessageContext {
        ctx(
            bytes,
            ConfLevel::Public,
            IntegLevel::Trusted,
            DerivationClass::Deterministic,
        )
    }

    // ── Size gate ────────────────────────────────────────────────────────

    #[test]
    fn oversized_message_is_denied() {
        let policy = AgentMessagePolicy {
            max_bytes: 1024,
            allow_secret: true,
            require_approval_for_untrusted: false,
        };
        let result = policy.evaluate(&clean(2048));
        assert!(result.is_deny());
        let CheckResult::Deny(reason) = result else {
            panic!()
        };
        assert!(reason.contains("2048"));
    }

    #[test]
    fn exactly_at_limit_is_allowed() {
        let policy = AgentMessagePolicy {
            max_bytes: 1024,
            allow_secret: true,
            require_approval_for_untrusted: false,
        };
        assert!(policy.evaluate(&clean(1024)).is_allow());
    }

    // ── Confidentiality gate ─────────────────────────────────────────────

    #[test]
    fn secret_denied_when_not_allowed() {
        let policy = AgentMessagePolicy {
            max_bytes: usize::MAX,
            allow_secret: false,
            require_approval_for_untrusted: false,
        };
        let c = ctx(
            100,
            ConfLevel::Secret,
            IntegLevel::Trusted,
            DerivationClass::Deterministic,
        );
        assert!(policy.evaluate(&c).is_deny());
    }

    #[test]
    fn secret_allowed_when_policy_permits() {
        let policy = AgentMessagePolicy {
            max_bytes: usize::MAX,
            allow_secret: true,
            require_approval_for_untrusted: false,
        };
        let c = ctx(
            100,
            ConfLevel::Secret,
            IntegLevel::Trusted,
            DerivationClass::Deterministic,
        );
        assert!(policy.evaluate(&c).is_allow());
    }

    #[test]
    fn internal_conf_not_affected_by_secret_gate() {
        let policy = AgentMessagePolicy::strict();
        let c = ctx(
            100,
            ConfLevel::Internal,
            IntegLevel::Trusted,
            DerivationClass::Deterministic,
        );
        assert!(policy.evaluate(&c).is_allow());
    }

    // ── Adversarial gate ─────────────────────────────────────────────────

    #[test]
    fn adversarial_always_denied() {
        let permissive = AgentMessagePolicy::permissive();
        let c = ctx(
            100,
            ConfLevel::Public,
            IntegLevel::Adversarial,
            DerivationClass::OpaqueExternal,
        );
        assert!(permissive.evaluate(&c).is_deny());
    }

    #[test]
    fn adversarial_denied_even_when_approval_gate_off() {
        let policy = AgentMessagePolicy {
            max_bytes: usize::MAX,
            allow_secret: true,
            require_approval_for_untrusted: false,
        };
        let c = ctx(
            100,
            ConfLevel::Public,
            IntegLevel::Adversarial,
            DerivationClass::Deterministic,
        );
        assert!(policy.evaluate(&c).is_deny());
    }

    // ── Approval gate ─────────────────────────────────────────────────────

    #[test]
    fn untrusted_requires_approval_when_gate_on() {
        let policy = AgentMessagePolicy {
            max_bytes: usize::MAX,
            allow_secret: true,
            require_approval_for_untrusted: true,
        };
        let c = ctx(
            100,
            ConfLevel::Public,
            IntegLevel::Untrusted,
            DerivationClass::Deterministic,
        );
        let result = policy.evaluate(&c);
        assert!(matches!(result, CheckResult::RequiresApproval(_)));
    }

    #[test]
    fn untrusted_allowed_when_gate_off() {
        let policy = AgentMessagePolicy {
            max_bytes: usize::MAX,
            allow_secret: true,
            require_approval_for_untrusted: false,
        };
        let c = ctx(
            100,
            ConfLevel::Public,
            IntegLevel::Untrusted,
            DerivationClass::Deterministic,
        );
        assert!(policy.evaluate(&c).is_allow());
    }

    #[test]
    fn opaque_external_requires_approval_when_gate_on() {
        let policy = AgentMessagePolicy {
            max_bytes: usize::MAX,
            allow_secret: true,
            require_approval_for_untrusted: true,
        };
        let c = ctx(
            100,
            ConfLevel::Public,
            IntegLevel::Trusted,
            DerivationClass::OpaqueExternal,
        );
        let result = policy.evaluate(&c);
        assert!(matches!(result, CheckResult::RequiresApproval(_)));
    }

    #[test]
    fn ai_derived_trusted_integ_allowed_when_gate_off() {
        let policy = AgentMessagePolicy {
            max_bytes: usize::MAX,
            allow_secret: true,
            require_approval_for_untrusted: false,
        };
        let c = ctx(
            100,
            ConfLevel::Public,
            IntegLevel::Trusted,
            DerivationClass::AIDerived,
        );
        assert!(policy.evaluate(&c).is_allow());
    }

    // ── Permissive / strict presets ───────────────────────────────────────

    #[test]
    fn permissive_allows_clean_message() {
        assert!(
            AgentMessagePolicy::permissive()
                .evaluate(&clean(1_000_000))
                .is_allow()
        );
    }

    #[test]
    fn strict_denies_over_4096() {
        assert!(
            AgentMessagePolicy::strict()
                .evaluate(&clean(5000))
                .is_deny()
        );
    }

    #[test]
    fn strict_denies_secret() {
        let c = ctx(
            100,
            ConfLevel::Secret,
            IntegLevel::Trusted,
            DerivationClass::Deterministic,
        );
        assert!(AgentMessagePolicy::strict().evaluate(&c).is_deny());
    }

    #[test]
    fn strict_requires_approval_for_untrusted() {
        let c = ctx(
            100,
            ConfLevel::Public,
            IntegLevel::Untrusted,
            DerivationClass::Deterministic,
        );
        assert!(matches!(
            AgentMessagePolicy::strict().evaluate(&c),
            CheckResult::RequiresApproval(_)
        ));
    }

    // ── Audit line ───────────────────────────────────────────────────────

    #[test]
    fn audit_line_includes_verdict_and_labels() {
        let policy = AgentMessagePolicy::strict();
        let c = clean(100);
        let result = policy.evaluate(&c);
        let line = policy.audit_line(&c, &result);
        assert!(line.contains("ALLOW"));
        assert!(line.contains("agent-b"));
        assert!(line.contains("Public"));
        assert!(line.contains("Trusted"));
    }

    #[test]
    fn audit_line_deny_verdict() {
        let policy = AgentMessagePolicy::strict();
        let c = clean(9999);
        let result = policy.evaluate(&c);
        let line = policy.audit_line(&c, &result);
        assert!(line.contains("DENY"));
    }

    // ── MessageContext helpers ────────────────────────────────────────────

    #[test]
    fn context_is_adversarial() {
        let c = ctx(
            10,
            ConfLevel::Public,
            IntegLevel::Adversarial,
            DerivationClass::OpaqueExternal,
        );
        assert!(c.is_adversarial());
        assert!(c.is_untrusted());
        assert!(!c.is_secret());
    }

    #[test]
    fn context_is_nondeterministic() {
        let c = ctx(
            10,
            ConfLevel::Public,
            IntegLevel::Trusted,
            DerivationClass::AIDerived,
        );
        assert!(c.is_nondeterministic());
    }
}
