//! One refusal, one explanation.
//!
//! [`DenyReason`] is the kernel's answer to "why not", and until this module it
//! had **no `Display`** — so every surface that had to show a refusal wrote its
//! own rendering, and they disagreed:
//!
//! | surface | what a person saw |
//! |---|---|
//! | the escalation proposal | `no granted effect admits egress to api.github.com (not in allowlist)` |
//! | the HTTP tool proxy | `EgressBlocked { host: "api.github.com", policy_reason: "not in allowlist" }` |
//! | the MCP server | `egress blocked: api.github.com — not in allowlist` |
//!
//! Three renderings of one fact, one of them Rust `Debug` syntax on the wire,
//! and the best of the three unreachable from the live path. This is the same
//! shape as #2406 — several components each rendering the same thing their own
//! way, with nothing comparing them — and it has the same remedy: one producer,
//! and a test that compares the producers rather than a literal.
//!
//! # What this is not
//!
//! It is not the refusal *code*. `gate_class::deny_code` owns those, they are
//! stable, and callers branch on them. This module owns only the sentence a
//! person reads, so a reword can never become a re-classification.

use std::fmt;

use crate::grant_usage::operation_name;
use crate::kernel::DenyReason;
use crate::Operation;

impl DenyReason {
    /// The sentence a person reads.
    ///
    /// `op` is the operation that was refused, when the caller knows it. Only
    /// two of the nineteen reasons are worded differently with it — a
    /// capability held at `never`, and an isolation dimension that makes an
    /// operation impossible — because the rest are about the *subject* or the
    /// policy rather than the verb. Callers that have the operation should pass
    /// it; [`fmt::Display`] passes `None` and says "this operation".
    ///
    /// Every arm is spelled out rather than falling through a catch-all, on the
    /// same reasoning as the deny-reason mapping in the tool proxy: a new
    /// refusal should not be able to acquire a rendering without somebody
    /// choosing one. A `_ =>` arm here would silently give the next variant the
    /// previous one's words.
    #[must_use]
    pub fn describe(&self, op: Option<Operation>) -> String {
        let name = op.map_or("this operation", operation_name);
        match self {
            Self::InsufficientCapability => format!("the grant holds {name} at never"),
            Self::BudgetExhausted { remaining_usd } => {
                format!("the grant's budget is exhausted (${remaining_usd} left)")
            }
            Self::TimeExpired { expired_at } => {
                format!(
                    "the grant expired at {}",
                    expired_at.format("%Y-%m-%d %H:%M UTC")
                )
            }
            Self::PathBlocked { path, denial } => match denial {
                Some(d) => format!("the path {path} is blocked ({d})"),
                None => format!("the path {path} is blocked"),
            },
            Self::CommandBlocked { command } => {
                format!("no granted effect vouches for the command `{command}`")
            }
            Self::IsolationInsufficient { required, actual } => {
                format!("the runtime isolation is {actual}, the policy requires {required}")
            }
            Self::IsolationGated { dimension } => {
                format!("the runtime's {dimension} isolation makes {name} impossible")
            }
            Self::EgressBlocked {
                host,
                policy_reason,
            } => format!("no granted effect admits egress to {host} ({policy_reason})"),
            Self::DlcAdmissionDenied { detail } => {
                format!("no signed admission credential covers it ({detail})")
            }
            Self::PolicyDenied {
                rule_name,
                sink_class,
            } => format!("admissibility rule '{rule_name}' denies sink {sink_class}"),
            Self::EnterpriseBlocked { detail } => format!("enterprise policy: {detail}"),
            Self::DelegationDenied { detail } => format!("delegation constraint: {detail}"),
            Self::FlowViolation { rule, .. } => {
                format!("information-flow rule {rule}: the session's inputs would flow out")
            }
            Self::InvalidDeclassification { detail } => {
                format!("declassification rejected: {detail}")
            }
            Self::DeclassificationReplayed { target_node } => {
                format!("the declassification token for {target_node} was already used")
            }
            Self::SinkScopeDenied { dimension, detail } => {
                format!("the certificate's {dimension} scope excludes it ({detail})")
            }
            Self::ActionTermRejected { detail } => {
                format!("preflight obligation failed: {detail}")
            }
            Self::IfcUnsafe { detail } => {
                format!("information-flow control: {detail}")
            }
            Self::CedarDenied { detail } => format!("no Cedar permit covers it ({detail})"),
        }
    }
}

impl fmt::Display for DenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.describe(None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::DenyReason;
    use chrono::Utc;

    /// One of every variant. Kept exhaustive by construction: the compiler
    /// cannot check that a *list* is complete, so the test below walks this and
    /// asserts the count, and the count is the thing a new variant changes.
    fn every_reason() -> Vec<DenyReason> {
        vec![
            DenyReason::InsufficientCapability,
            DenyReason::BudgetExhausted {
                remaining_usd: "1.25".into(),
            },
            DenyReason::TimeExpired {
                expired_at: Utc::now(),
            },
            DenyReason::PathBlocked {
                path: ".ssh/id_rsa".into(),
                denial: None,
            },
            DenyReason::CommandBlocked {
                command: "rm -rf /".into(),
            },
            DenyReason::IsolationInsufficient {
                required: "microvm".into(),
                actual: "unsandboxed".into(),
            },
            DenyReason::IsolationGated {
                dimension: "network".into(),
            },
            DenyReason::EgressBlocked {
                host: "api.github.com".into(),
                policy_reason: "not in allowlist".into(),
            },
            DenyReason::DlcAdmissionDenied {
                detail: "no issuer-signed credential".into(),
            },
            DenyReason::PolicyDenied {
                rule_name: "no-exfil".into(),
                sink_class: "http_egress".into(),
            },
            DenyReason::EnterpriseBlocked {
                detail: "org policy".into(),
            },
            DenyReason::DelegationDenied {
                detail: "beyond the ceiling".into(),
            },
            DenyReason::FlowViolation {
                rule: "R3".into(),
                receipt: None,
            },
            DenyReason::InvalidDeclassification {
                detail: "bad signature".into(),
            },
            DenyReason::DeclassificationReplayed {
                target_node: "n7".into(),
            },
            DenyReason::SinkScopeDenied {
                dimension: "hosts".into(),
                detail: "api.example not in scope".into(),
            },
            DenyReason::ActionTermRejected {
                detail: "InScopeWithTask".into(),
            },
            DenyReason::IfcUnsafe {
                detail: "adversarial ancestry".into(),
            },
            DenyReason::CedarDenied {
                detail: "no permit".into(),
            },
        ]
    }

    /// A new `DenyReason` variant must come here and be given words. The
    /// failure mode this guards is the one that produced the mess: a variant
    /// added upstream, rendered by nobody, reaching a person as whatever the
    /// nearest catch-all happened to say.
    #[test]
    fn every_variant_has_words() {
        let all = every_reason();
        assert_eq!(
            all.len(),
            19,
            "DenyReason gained or lost a variant; add it to `every_reason` and give it a sentence"
        );
        for r in &all {
            let s = r.describe(None);
            assert!(!s.trim().is_empty(), "{r:?} renders empty");
        }
    }

    /// THE property. `Debug` on the wire is what this module exists to end, and
    /// the tell is a brace: every `Debug` rendering of these variants contains
    /// one, and no prose sentence does.
    #[test]
    fn no_variant_leaks_debug_syntax() {
        for r in every_reason() {
            let s = r.describe(None);
            assert!(
                !s.contains('{') && !s.contains('}'),
                "{r:?} leaks Debug syntax into a person's sentence: {s}"
            );
            assert!(!s.contains(" { "), "{r:?} renders as a struct literal: {s}");
        }
    }

    /// Non-vacuity for the pair above: distinct reasons say distinct things, so
    /// the tests are not satisfiable by a constant string.
    #[test]
    fn distinct_reasons_read_differently() {
        let all = every_reason();
        let mut seen: Vec<String> = all.iter().map(|r| r.describe(None)).collect();
        seen.sort();
        let before = seen.len();
        seen.dedup();
        assert_eq!(before, seen.len(), "two reasons render identically");
    }

    /// The operation changes the two arms it should, and no others.
    #[test]
    fn only_the_operation_dependent_arms_move() {
        let op = Some(Operation::WebFetch);
        let mut moved = 0;
        for r in every_reason() {
            if r.describe(None) != r.describe(op) {
                moved += 1;
            }
        }
        assert_eq!(
            moved, 2,
            "exactly `InsufficientCapability` and `IsolationGated` are worded with the operation"
        );
    }

    #[test]
    fn display_matches_describe_with_no_operation() {
        for r in every_reason() {
            assert_eq!(r.to_string(), r.describe(None));
        }
    }
}
