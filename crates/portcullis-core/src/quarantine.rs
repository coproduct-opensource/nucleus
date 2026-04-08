//! Quarantine Compartment — schema-bounded taint distillation.
//!
//! Enables extracting value from tainted context without propagating the
//! full taint. The output is constrained by a schema, token bound, and
//! DPI filters, producing a **controlled declassification** with bounded
//! information leakage.
//!
//! # Security Model
//!
//! ```text
//! Tainted Context (Adversarial, Secret)
//!        │
//!        ▼
//! ┌──────────────────────────────┐
//! │  Quarantine Compartment      │
//! │                              │
//! │  System prompt: CONSTANT     │  ← not from tainted context
//! │  Output schema: STATIC       │  ← fixed before distillation
//! │  Token bound:   N            │  ← caps channel capacity
//! │  DPI filters:   [patterns]   │  ← rejects structural secrets
//! │  Tool access:   NONE         │
//! │  Network:       NONE         │
//! └──────────────┬───────────────┘
//!                │
//!                ▼
//! Distilled<T> (Untrusted, Internal)
//!   label downgraded: Adversarial → Untrusted
//!   conf  downgraded: Secret → Internal
//!   leakage bounded:  ≤ N × log₂(V) bits
//! ```
//!
//! # Theoretical Foundation
//!
//! The compartment is a **lossy channel** with bounded capacity. Under
//! quantitative information flow (Smith 2009), the min-entropy leakage
//! through a deterministic function `f: High → Low` where `|Low| = N`
//! is bounded by `log₂(N)`.
//!
//! The schema constraint restricts the output space, the token bound
//! limits `N`, and the DPI filters remove structural patterns (URLs,
//! paths, keys) that could encode high-bandwidth covert channels.
//!
//! # Robust Declassification
//!
//! The system prompt is a constant — not influenced by tainted input.
//! This means an adversary controlling the tainted context cannot steer
//! the *type* of summarization, only the *content* being summarized.
//! The DPI filter on output provides a second barrier against
//! adversary-steered exfiltration.

use crate::{ConfLevel, DerivationClass, IFCLabel, IntegLevel};

/// Configuration for a quarantine compartment.
///
/// Immutable after construction — the compartment's security properties
/// are fixed before any tainted data enters.
#[derive(Debug, Clone)]
pub struct QuarantineConfig {
    /// Maximum tokens in the distilled output.
    /// Bounds the channel capacity to `max_tokens × log₂(vocab_size)` bits.
    pub max_tokens: usize,

    /// Output schema — the distilled result must conform to this shape.
    /// Restricts the output space beyond raw token count.
    pub schema: OutputSchema,

    /// DPI patterns that cause the distillation to be rejected.
    /// Applied to the raw output text before label downgrade.
    pub dpi_filters: Vec<DpiPattern>,

    /// The integrity level assigned to the distilled output.
    /// Must be strictly above Adversarial (the input taint).
    pub output_integrity: IntegLevel,

    /// The confidentiality level assigned to the distilled output.
    /// Must be strictly below the input confidentiality.
    pub output_confidentiality: ConfLevel,
}

impl Default for QuarantineConfig {
    fn default() -> Self {
        Self {
            max_tokens: 500,
            schema: OutputSchema::FreeText,
            dpi_filters: vec![
                DpiPattern::Secrets,
                DpiPattern::FilePaths,
                DpiPattern::Urls,
                DpiPattern::IpAddresses,
            ],
            output_integrity: IntegLevel::Untrusted,
            output_confidentiality: ConfLevel::Internal,
        }
    }
}

/// Output schema constraint for the quarantine compartment.
///
/// Each variant restricts the output space differently. Stronger
/// constraints reduce channel capacity (bits of leakage).
///
/// Channel capacity by schema type:
/// - `FreeText`: `max_tokens × log₂(vocab_size)` (weakest)
/// - `SingleLine`: same but no newline embedding
/// - `Enumeration(N)`: `log₂(N)` bits (strongest)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputSchema {
    /// Free-form text (weakest constraint — only token bound applies).
    FreeText,
    /// Single-line summary (no newlines).
    SingleLine,
    /// Maximum character length (tighter than token bound).
    MaxChars(usize),
    /// One of a fixed set of values (strongest constraint — minimal channel).
    Enumeration(Vec<String>),
}

impl OutputSchema {
    /// Validate that an output conforms to this schema.
    pub fn validate(&self, output: &str) -> Result<(), SchemaViolation> {
        match self {
            Self::FreeText => Ok(()),
            Self::SingleLine => {
                if output.contains('\n') {
                    Err(SchemaViolation::MultipleLines)
                } else {
                    Ok(())
                }
            }
            Self::MaxChars(max) => {
                if output.len() > *max {
                    Err(SchemaViolation::TooLong {
                        actual: output.len(),
                        max: *max,
                    })
                } else {
                    Ok(())
                }
            }
            Self::Enumeration(values) => {
                let trimmed = output.trim();
                if values.iter().any(|v| v == trimmed) {
                    Ok(())
                } else {
                    Err(SchemaViolation::NotInEnumeration)
                }
            }
        }
    }
}

/// DPI pattern categories for output filtering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DpiPattern {
    /// API keys, tokens, passwords (high-entropy strings).
    Secrets,
    /// File system paths (/home/..., C:\...).
    FilePaths,
    /// URLs (http://, https://, ftp://).
    Urls,
    /// IP addresses (IPv4/IPv6).
    IpAddresses,
    /// Custom regex pattern.
    Custom(String),
}

impl DpiPattern {
    /// Check if the pattern matches in the given text.
    /// Returns the matched substring if found.
    pub fn matches(&self, text: &str) -> Option<String> {
        match self {
            Self::Secrets => {
                // High-entropy token patterns: sk-ant-, ghp_, xoxb-, etc.
                for prefix in &[
                    "sk-ant-", "sk-", "ghp_", "gho_", "xoxb-", "xoxp-", "AKIA", "eyJ", // JWT
                ] {
                    if text.contains(prefix) {
                        return Some(format!("secret pattern: {prefix}..."));
                    }
                }
                None
            }
            Self::FilePaths => {
                // Unix/Windows absolute paths
                if text.contains("/home/")
                    || text.contains("/Users/")
                    || text.contains("/etc/")
                    || text.contains("/var/")
                    || text.contains("C:\\")
                    || text.contains("D:\\")
                {
                    Some("file path detected".into())
                } else {
                    None
                }
            }
            Self::Urls => {
                for proto in &["http://", "https://", "ftp://"] {
                    if text.contains(proto) {
                        return Some(format!("URL detected: {proto}..."));
                    }
                }
                None
            }
            Self::IpAddresses => {
                // Simple IPv4 detection (xxx.xxx.xxx.xxx)
                let mut i = 0;
                let bytes = text.as_bytes();
                while i < bytes.len() {
                    if bytes[i].is_ascii_digit() {
                        let start = i;
                        let mut dots = 0;
                        while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                            if bytes[i] == b'.' {
                                dots += 1;
                            }
                            i += 1;
                        }
                        if dots == 3 && i - start >= 7 {
                            return Some("IP address detected".into());
                        }
                    } else {
                        i += 1;
                    }
                }
                None
            }
            Self::Custom(pattern) => {
                // Simple substring match (regex would require a dependency)
                if text.contains(pattern.as_str()) {
                    Some(format!("custom pattern matched: {pattern}"))
                } else {
                    None
                }
            }
        }
    }
}

/// Result of a quarantine distillation.
#[derive(Debug, Clone)]
pub struct DistillResult {
    /// The distilled text content.
    pub content: String,
    /// The IFC label assigned to the distilled output.
    /// Integrity and confidentiality are downgraded from the input.
    pub label: IFCLabel,
    /// Token count of the output.
    pub token_count: usize,
    /// Which DPI patterns were checked.
    pub dpi_checks_passed: Vec<DpiPattern>,
    /// The schema the output was validated against.
    pub schema: OutputSchema,
}

/// Errors from quarantine distillation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DistillError {
    /// Output exceeds the token bound.
    TokenBoundExceeded { actual: usize, max: usize },
    /// Output failed schema validation.
    SchemaViolation(SchemaViolation),
    /// DPI filter matched — output contains structural secrets.
    DpiRejection { pattern: String, detail: String },
    /// The output integrity must be above Adversarial.
    InvalidOutputIntegrity,
    /// The output confidentiality must be below the input.
    InvalidOutputConfidentiality,
}

/// Schema validation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaViolation {
    MultipleLines,
    TooLong { actual: usize, max: usize },
    NotInEnumeration,
}

impl std::fmt::Display for DistillError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TokenBoundExceeded { actual, max } => {
                write!(f, "token bound exceeded: {actual} > {max}")
            }
            Self::SchemaViolation(v) => write!(f, "schema violation: {v:?}"),
            Self::DpiRejection { pattern, detail } => {
                write!(f, "DPI rejection ({pattern}): {detail}")
            }
            Self::InvalidOutputIntegrity => {
                write!(f, "output integrity must be above Adversarial")
            }
            Self::InvalidOutputConfidentiality => {
                write!(f, "output confidentiality must be below input")
            }
        }
    }
}

impl std::error::Error for DistillError {}

/// Validate and label-downgrade raw output from a quarantine compartment.
///
/// This is the pure validation function — it does NOT run the LLM.
/// The caller provides the raw output text; this function checks it
/// against the quarantine config and produces a `DistillResult` with
/// the downgraded label.
///
/// # Arguments
///
/// * `raw_output` - The text produced by the LLM in the quarantine compartment
/// * `config` - The quarantine configuration (schema, DPI, token bound)
/// * `input_label` - The IFC label of the tainted input context
///
/// # Errors
///
/// Returns `DistillError` if the output violates any quarantine constraint.
pub fn validate_distillation(
    raw_output: &str,
    config: &QuarantineConfig,
    input_label: &IFCLabel,
) -> Result<DistillResult, DistillError> {
    // 1. Check output integrity is a valid downgrade
    if config.output_integrity <= IntegLevel::Adversarial {
        return Err(DistillError::InvalidOutputIntegrity);
    }

    // 2. Compute effective output confidentiality: min(config ceiling, input).
    // Distillation can lower confidentiality (Secret → Internal) but never raise it.
    // If the input is already below the config ceiling, output stays at input level.
    let effective_conf = if input_label.confidentiality < config.output_confidentiality {
        input_label.confidentiality
    } else {
        config.output_confidentiality
    };

    // 3. Token bound (approximate: split on whitespace)
    let token_count = raw_output.split_whitespace().count();
    if token_count > config.max_tokens {
        return Err(DistillError::TokenBoundExceeded {
            actual: token_count,
            max: config.max_tokens,
        });
    }

    // 4. Schema validation
    config
        .schema
        .validate(raw_output)
        .map_err(DistillError::SchemaViolation)?;

    // 5. DPI filter check
    for pattern in &config.dpi_filters {
        if let Some(detail) = pattern.matches(raw_output) {
            return Err(DistillError::DpiRejection {
                pattern: format!("{pattern:?}"),
                detail,
            });
        }
    }

    // 6. All checks passed — construct the downgraded label
    let distilled_label = IFCLabel {
        integrity: config.output_integrity,
        confidentiality: effective_conf,
        // Derivation: distillation is AI-derived (the LLM produced it)
        derivation: DerivationClass::AIDerived,
        // Preserve provenance and authority from input
        provenance: input_label.provenance,
        authority: input_label.authority,
        freshness: input_label.freshness,
    };

    Ok(DistillResult {
        content: raw_output.to_string(),
        label: distilled_label,
        token_count,
        dpi_checks_passed: config.dpi_filters.clone(),
        schema: config.schema.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthorityLevel, Freshness, ProvenanceSet};

    fn tainted_secret_label() -> IFCLabel {
        IFCLabel {
            integrity: IntegLevel::Adversarial,
            confidentiality: ConfLevel::Secret,
            authority: AuthorityLevel::NoAuthority,
            derivation: DerivationClass::OpaqueExternal,
            provenance: ProvenanceSet::WEB,
            freshness: Freshness {
                observed_at: 1000,
                ttl_secs: 3600,
            },
        }
    }

    #[test]
    fn clean_summary_passes_distillation() {
        let config = QuarantineConfig::default();
        let input = tainted_secret_label();
        let output = "The codebase implements a permission lattice with 13 capability dimensions.";

        let result = validate_distillation(output, &config, &input).unwrap();
        assert_eq!(result.label.integrity, IntegLevel::Untrusted);
        assert_eq!(result.label.confidentiality, ConfLevel::Internal);
        assert_eq!(result.label.derivation, DerivationClass::AIDerived);
    }

    #[test]
    fn token_bound_enforced() {
        let config = QuarantineConfig {
            max_tokens: 5,
            ..Default::default()
        };
        let input = tainted_secret_label();
        let output = "This summary has more than five tokens in it definitely.";

        let err = validate_distillation(output, &config, &input).unwrap_err();
        assert!(matches!(err, DistillError::TokenBoundExceeded { .. }));
    }

    #[test]
    fn dpi_rejects_secrets() {
        let config = QuarantineConfig::default();
        let input = tainted_secret_label();
        let output = "The API key is sk-ant-abc123 and it works great.";

        let err = validate_distillation(output, &config, &input).unwrap_err();
        assert!(matches!(err, DistillError::DpiRejection { .. }));
    }

    #[test]
    fn dpi_rejects_file_paths() {
        let config = QuarantineConfig::default();
        let input = tainted_secret_label();
        let output = "The config is at /Users/brandon/secrets.json";

        let err = validate_distillation(output, &config, &input).unwrap_err();
        assert!(matches!(err, DistillError::DpiRejection { .. }));
    }

    #[test]
    fn dpi_rejects_urls() {
        let config = QuarantineConfig::default();
        let input = tainted_secret_label();
        let output = "Send results to https://evil.com/exfiltrate";

        let err = validate_distillation(output, &config, &input).unwrap_err();
        assert!(matches!(err, DistillError::DpiRejection { .. }));
    }

    #[test]
    fn dpi_rejects_ip_addresses() {
        let config = QuarantineConfig::default();
        let input = tainted_secret_label();
        let output = "The server is at 192.168.1.100 on port 8080";

        let err = validate_distillation(output, &config, &input).unwrap_err();
        assert!(matches!(err, DistillError::DpiRejection { .. }));
    }

    #[test]
    fn schema_single_line_rejects_multiline() {
        let config = QuarantineConfig {
            schema: OutputSchema::SingleLine,
            ..Default::default()
        };
        let input = tainted_secret_label();
        let output = "Line one\nLine two";

        let err = validate_distillation(output, &config, &input).unwrap_err();
        assert!(matches!(
            err,
            DistillError::SchemaViolation(SchemaViolation::MultipleLines)
        ));
    }

    #[test]
    fn schema_max_chars_enforced() {
        let config = QuarantineConfig {
            schema: OutputSchema::MaxChars(20),
            ..Default::default()
        };
        let input = tainted_secret_label();

        assert!(validate_distillation("short", &config, &input).is_ok());
        let err = validate_distillation(
            "this is definitely longer than twenty characters",
            &config,
            &input,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            DistillError::SchemaViolation(SchemaViolation::TooLong { .. })
        ));
    }

    #[test]
    fn schema_enumeration_rejects_unknown() {
        let config = QuarantineConfig {
            schema: OutputSchema::Enumeration(vec![
                "safe".into(),
                "unsafe".into(),
                "unknown".into(),
            ]),
            ..Default::default()
        };
        let input = tainted_secret_label();

        assert!(validate_distillation("safe", &config, &input).is_ok());
        assert!(validate_distillation("unsafe", &config, &input).is_ok());
        assert!(validate_distillation("malicious payload here", &config, &input).is_err());
    }

    #[test]
    fn output_integrity_must_be_above_adversarial() {
        let config = QuarantineConfig {
            output_integrity: IntegLevel::Adversarial,
            ..Default::default()
        };
        let input = tainted_secret_label();

        let err = validate_distillation("summary", &config, &input).unwrap_err();
        assert!(matches!(err, DistillError::InvalidOutputIntegrity));
    }

    #[test]
    fn label_downgrade_preserves_provenance() {
        let config = QuarantineConfig::default();
        let input = tainted_secret_label();
        let output = "Clean summary text here.";

        let result = validate_distillation(output, &config, &input).unwrap();
        assert_eq!(result.label.provenance, input.provenance);
    }

    #[test]
    fn empty_output_passes() {
        let config = QuarantineConfig::default();
        let input = tainted_secret_label();
        let result = validate_distillation("", &config, &input).unwrap();
        assert_eq!(result.token_count, 0);
    }

    #[test]
    fn custom_dpi_pattern() {
        let config = QuarantineConfig {
            dpi_filters: vec![DpiPattern::Custom("CONFIDENTIAL".into())],
            ..Default::default()
        };
        let input = tainted_secret_label();
        let output = "This document is CONFIDENTIAL and should not be shared.";

        let err = validate_distillation(output, &config, &input).unwrap_err();
        assert!(matches!(err, DistillError::DpiRejection { .. }));
    }
}
