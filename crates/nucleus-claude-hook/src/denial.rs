//! Human-readable denial formatting.
//!
//! Converts `DenyReason` variants into actionable messages for Claude Code
//! users, including "How to fix" guidance for each denial type.

use portcullis::Operation;

/// Format a denial reason as a human-readable message for Claude Code users.
///
/// Instead of raw Rust Debug output like `FlowViolation { rule: "AuthorityEscalation" }`,
/// produce actionable messages like "Blocked: this write depends on web content."
pub(crate) fn format_denial_for_user(
    reason: &portcullis::kernel::DenyReason,
    operation: Operation,
    compartment: Option<&str>,
) -> String {
    use portcullis::kernel::DenyReason;

    let comp_hint = compartment
        .map(|c| format!(" (compartment: {c})"))
        .unwrap_or_default();

    match reason {
        DenyReason::InsufficientCapability => {
            let fix = match compartment {
                Some("research") => "\n  How to fix:\n  \
                    - Switch to 'draft' compartment (enables writes) or 'execute' (enables bash)\n  \
                    - Or change the profile to allow this operation in .nucleus/policy.toml",
                Some("draft") if operation == Operation::RunBash => "\n  How to fix:\n  \
                    - Switch to 'execute' compartment to run commands\n  \
                    - Draft compartment only allows read + write (no execution)",
                Some("draft") if matches!(operation, Operation::WebFetch | Operation::WebSearch) => {
                    "\n  How to fix:\n  \
                    - Switch to 'research' compartment for web access\n  \
                    - Draft compartment blocks web to prevent taint"
                }
                _ => "\n  How to fix:\n  \
                    - Change the profile's capability for this operation in .nucleus/policy.toml\n  \
                    - Or use a more permissive profile: NUCLEUS_PROFILE=permissive",
            };
            format!("Blocked: {operation} is not allowed in the current profile{comp_hint}.{fix}")
        }
        DenyReason::FlowViolation { rule, .. } => {
            let (explanation, fix) = if rule.contains("AuthorityEscalation") {
                (
                    "This operation depends on web content (adversarial/untrusted). \
                     Web-influenced data cannot steer writes, execution, or git operations.",
                    if compartment.is_some() {
                        "\n  How to fix:\n  \
                        - Switch to 'draft' compartment (resets the flow graph, clears taint)\n  \
                        - Or use separate sessions: research in one, code in another"
                    } else {
                        "\n  How to fix:\n  \
                        - Restart Claude Code to clear the taint and try again\n  \
                        - Or use separate sessions: research in one, code in another\n  \
                        - Or enable compartments: NUCLEUS_COMPARTMENT=research"
                    },
                )
            } else if rule.contains("Exfiltration") {
                (
                    "This operation would exfiltrate secret data to an external sink.",
                    "\n  How to fix:\n  \
                    - Avoid mixing secret file reads with network operations in the same session\n  \
                    - Or declassify the data if it's not actually secret",
                )
            } else if rule.contains("IntegrityViolation") {
                (
                    "This operation would use untrusted data in a trusted-only context.",
                    "\n  How to fix:\n  \
                    - Validate or re-derive the data from a trusted source\n  \
                    - Or switch compartments to reset the flow graph",
                )
            } else {
                (
                    "Information flow policy prevents this operation.",
                    "\n  How to fix:\n  \
                    - Restart the session or switch compartments to clear taint",
                )
            };
            format!("Blocked: {explanation}{comp_hint}{fix}")
        }
        DenyReason::CommandBlocked { command } => {
            let short_cmd = if command.len() > 60 {
                format!("{}...", &command[..57])
            } else {
                command.clone()
            };
            format!(
                "Blocked: command '{short_cmd}' is not allowed by the command policy{comp_hint}.\n  \
                How to fix:\n  \
                - Add the command to the allowlist in .nucleus/policy.toml under [profile.commands]\n  \
                - Or use a more permissive profile"
            )
        }
        DenyReason::PathBlocked { path } => {
            format!(
                "Blocked: access to '{path}' is restricted by path policy{comp_hint}.\n  \
                How to fix:\n  \
                - Add the path to [profile.paths.allowed] in .nucleus/policy.toml\n  \
                - Or remove it from [profile.paths.blocked]"
            )
        }
        DenyReason::BudgetExhausted { remaining_usd } => {
            format!(
                "Blocked: budget exhausted (remaining: ${remaining_usd}).\n  \
                How to fix:\n  \
                - Increase max_cost_usd in .nucleus/policy.toml\n  \
                - Or start a new session with a fresh budget"
            )
        }
        DenyReason::TimeExpired { expired_at } => {
            format!(
                "Blocked: session expired at {expired_at}.\n  \
                How to fix:\n  \
                - Start a new session (restart Claude Code)\n  \
                - Or increase duration_hours in .nucleus/policy.toml"
            )
        }
        DenyReason::IsolationInsufficient { required, actual } => {
            format!(
                "Blocked: requires {required} isolation but running in {actual}.\n  \
                How to fix:\n  \
                - Run in a container (Docker/Colima) or Firecracker microVM\n  \
                - Or lower the minimum isolation in the policy"
            )
        }
        DenyReason::IsolationGated { dimension } => {
            format!(
                "Blocked: {dimension} is not available in the current isolation level.\n  \
                How to fix:\n  \
                - Run in a higher isolation environment (container or microVM)"
            )
        }
        DenyReason::EgressBlocked { policy_reason, .. } => format!(
            "{policy_reason}\n  How to fix:\n  \
            - Add the host to allowed_hosts in .nucleus/egress.toml\n  \
            - Or remove egress.toml to disable egress filtering"
        ),
        DenyReason::PolicyDenied {
            rule_name,
            sink_class,
        } => {
            format!(
                "Blocked: admissibility rule '{rule_name}' denied this operation (sink: {sink_class}){comp_hint}.\n  \
                How to fix:\n  \
                - Review the rule in .nucleus/policy.toml under [[admissibility]]\n  \
                - Adjust source_predicate or artifact_predicate to match your data labels\n  \
                - Or change the rule's verdict to 'allow' or 'requires_approval'"
            )
        }
        DenyReason::EnterpriseBlocked { detail } => {
            format!(
                "Blocked: enterprise policy denied this operation: {detail}{comp_hint}.\n  \
                How to fix:\n  \
                - Ask your organization admin to update .nucleus/enterprise.toml\n  \
                - Add the sink class to allowed_sinks or remove it from denied_sinks"
            )
        }
        DenyReason::DelegationDenied { detail } => {
            format!(
                "Blocked: delegation constraint violated: {detail}{comp_hint}.\n  \
                How to fix:\n  \
                - Check that the delegation has not expired\n  \
                - Ensure the delegation depth has not been exhausted\n  \
                - Verify AgentSpawn is in the delegation scope's allowed_sinks"
            )
        }
        DenyReason::InvalidDeclassification { detail } => {
            format!(
                "Blocked: declassification token rejected: {detail}{comp_hint}.\n  \
                How to fix:\n  \
                - Ensure the declassification token is signed by a trusted key\n  \
                - Check that set_trusted_keys() includes the signing key's public key"
            )
        }
        DenyReason::SinkScopeDenied {
            dimension, detail, ..
        } => {
            format!(
                "Blocked: certificate sink scope denied ({dimension}): {detail}{comp_hint}.\n  \
                How to fix:\n  \
                - Check the delegation certificate's sink_scope restrictions\n  \
                - Ensure the target {dimension} is in the allowed list"
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use portcullis::kernel::DenyReason;

    #[test]
    fn test_denial_messages_include_how_to_fix() {
        // Capability denial
        let msg = format_denial_for_user(
            &DenyReason::InsufficientCapability,
            Operation::RunBash,
            Some("draft"),
        );
        assert!(msg.contains("How to fix"), "capability denial: {msg}");
        assert!(
            msg.contains("execute"),
            "should suggest execute compartment"
        );

        // Flow violation (web taint)
        let msg = format_denial_for_user(
            &DenyReason::FlowViolation {
                rule: "AuthorityEscalation".to_string(),
                receipt: None,
            },
            Operation::WriteFiles,
            Some("research"),
        );
        assert!(msg.contains("How to fix"), "flow violation: {msg}");
        assert!(msg.contains("draft"), "should suggest draft compartment");

        // Budget exhausted
        let msg = format_denial_for_user(
            &DenyReason::BudgetExhausted {
                remaining_usd: "0.00".to_string(),
            },
            Operation::ReadFiles,
            None,
        );
        assert!(msg.contains("How to fix"), "budget: {msg}");
        assert!(msg.contains("max_cost_usd"), "should mention config key");

        // Path blocked
        let msg = format_denial_for_user(
            &DenyReason::PathBlocked {
                path: "/etc/shadow".to_string(),
            },
            Operation::ReadFiles,
            None,
        );
        assert!(msg.contains("How to fix"), "path blocked: {msg}");
        assert!(msg.contains("policy.toml"), "should mention config file");
    }
}
