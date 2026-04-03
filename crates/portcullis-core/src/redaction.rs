//! Confidentiality-aware redaction filter (#959).
//!
//! FIDES-style selective hiding: before an outbound action, strip or
//! replace field envelopes where the label's confidentiality exceeds
//! the action's maximum visible confidentiality level.
//!
//! This prevents slow exfiltration via legitimate tool calls that
//! might leak high-confidentiality data in their parameters.

use crate::{ConfLevel, IFCLabel};

/// Result of a redaction check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedactionResult {
    /// Data can pass through — confidentiality is within bounds.
    Pass,
    /// Data should be redacted — confidentiality exceeds the action's limit.
    Redact {
        /// The data's confidentiality level.
        data_conf: ConfLevel,
        /// The maximum allowed confidentiality for this action.
        max_visible: ConfLevel,
    },
}

impl RedactionResult {
    /// Whether the data should be redacted.
    pub fn should_redact(&self) -> bool {
        matches!(self, Self::Redact { .. })
    }
}

/// Check if data with the given label should be redacted before an action.
///
/// An action with `max_visible_conf` can only see data at or below that level.
/// Secret data cannot be sent to a tool that only handles Public data.
pub fn check_redaction(data_label: &IFCLabel, max_visible_conf: ConfLevel) -> RedactionResult {
    if data_label.confidentiality > max_visible_conf {
        RedactionResult::Redact {
            data_conf: data_label.confidentiality,
            max_visible: max_visible_conf,
        }
    } else {
        RedactionResult::Pass
    }
}

/// Redact a string value — replace with a placeholder.
pub fn redact_value(original: &str, conf_level: ConfLevel) -> String {
    format!("[REDACTED: conf={conf_level:?}, len={}]", original.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthorityLevel, DerivationClass, IntegLevel, ProvenanceSet};

    fn label(conf: ConfLevel) -> IFCLabel {
        IFCLabel {
            confidentiality: conf,
            integrity: IntegLevel::Trusted,
            provenance: ProvenanceSet::USER,
            freshness: crate::Freshness {
                observed_at: 0,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::Directive,
            derivation: DerivationClass::Deterministic,
        }
    }

    #[test]
    fn public_data_passes_public_action() {
        let result = check_redaction(&label(ConfLevel::Public), ConfLevel::Public);
        assert_eq!(result, RedactionResult::Pass);
    }

    #[test]
    fn secret_data_redacted_for_public_action() {
        let result = check_redaction(&label(ConfLevel::Secret), ConfLevel::Public);
        assert!(result.should_redact());
    }

    #[test]
    fn internal_data_passes_internal_action() {
        let result = check_redaction(&label(ConfLevel::Internal), ConfLevel::Internal);
        assert_eq!(result, RedactionResult::Pass);
    }

    #[test]
    fn secret_data_redacted_for_internal_action() {
        let result = check_redaction(&label(ConfLevel::Secret), ConfLevel::Internal);
        assert!(result.should_redact());
    }

    #[test]
    fn redact_value_preserves_length() {
        let redacted = redact_value("my secret api key", ConfLevel::Secret);
        assert!(redacted.contains("REDACTED"));
        assert!(redacted.contains("len=17"));
    }
}
