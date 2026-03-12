//! SARIF 2.1.0 output for nucleus-audit scan results.
//!
//! Converts [`ScanReport`] findings into the Static Analysis Results Interchange
//! Format (SARIF), enabling GitHub Code Scanning, GitLab SAST, Azure DevOps, and
//! other CI/CD platforms to display nucleus security findings as PR annotations.
//!
//! Spec: <https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html>

use serde::Serialize;

use crate::finding::{Finding, ScanReport, Severity};

/// Top-level SARIF log.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifLog {
    #[serde(rename = "$schema")]
    pub schema: &'static str,
    pub version: &'static str,
    pub runs: Vec<SarifRun>,
}

/// A single analysis run.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub invocations: Vec<SarifInvocation>,
}

/// Tool metadata.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifTool {
    pub driver: SarifToolComponent,
}

/// Tool component with rules.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifToolComponent {
    pub name: &'static str,
    pub semantic_version: &'static str,
    pub information_uri: &'static str,
    pub rules: Vec<SarifRule>,
}

/// A rule definition (finding category).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    pub short_description: SarifMessage,
    pub default_configuration: SarifRuleConfiguration,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<SarifMessage>,
}

/// Rule default configuration (severity level).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRuleConfiguration {
    pub level: &'static str,
}

/// A single result (finding instance).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifResult {
    pub rule_id: String,
    pub level: &'static str,
    pub message: SarifMessage,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<SarifLocation>,
}

/// A location reference.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifLocation {
    pub physical_location: SarifPhysicalLocation,
}

/// Physical file location.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifPhysicalLocation {
    pub artifact_location: SarifArtifactLocation,
}

/// Artifact URI.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifArtifactLocation {
    pub uri: String,
}

/// A text message.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifMessage {
    pub text: String,
}

/// Invocation metadata.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifInvocation {
    pub execution_successful: bool,
}

/// Map our Severity to SARIF level strings.
fn severity_to_sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// Normalize a finding category into a stable SARIF rule ID.
///
/// Rule IDs follow the pattern `nucleus/<category>`, e.g. `nucleus/credentials`,
/// `nucleus/trifecta`, `nucleus/network`.
fn rule_id_from_category(category: &str) -> String {
    format!("nucleus/{}", category.to_lowercase().replace(' ', "-"))
}

/// Human-friendly rule name from category.
fn rule_name_from_category(category: &str) -> String {
    category
        .split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(c) => c.to_uppercase().to_string() + chars.as_str(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Extract a file path from a finding title if it was attached by `attach_source_to_findings`.
///
/// Titles with source look like `[path/to/file.yaml] Original title`.
fn extract_source_path(finding: &Finding) -> Option<String> {
    if finding.title.starts_with('[') {
        if let Some(end) = finding.title.find(']') {
            let path = finding.title[1..end].trim().to_string();
            if !path.is_empty() {
                return Some(path);
            }
        }
    }
    None
}

/// Convert a [`ScanReport`] to a SARIF 2.1.0 log.
pub fn scan_report_to_sarif(report: &ScanReport) -> SarifLog {
    // Collect unique rules from findings
    let mut rule_ids: Vec<String> = Vec::new();
    let mut rules: Vec<SarifRule> = Vec::new();

    for finding in &report.findings {
        let id = rule_id_from_category(&finding.category);
        if !rule_ids.contains(&id) {
            rule_ids.push(id.clone());
            rules.push(SarifRule {
                id: id.clone(),
                name: rule_name_from_category(&finding.category),
                short_description: SarifMessage {
                    text: category_description(&finding.category),
                },
                default_configuration: SarifRuleConfiguration {
                    level: severity_to_sarif_level(&finding.severity),
                },
                help: None,
            });
        }
    }

    // Convert findings to results
    let results: Vec<SarifResult> = report
        .findings
        .iter()
        .map(|finding| {
            let locations = if let Some(path) = extract_source_path(finding) {
                vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation { uri: path },
                    },
                }]
            } else if report.scanned_sources.len() == 1 {
                vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: report.scanned_sources[0].clone(),
                        },
                    },
                }]
            } else {
                Vec::new()
            };

            SarifResult {
                rule_id: rule_id_from_category(&finding.category),
                level: severity_to_sarif_level(&finding.severity),
                message: SarifMessage {
                    text: format!("{}: {}", finding.title, finding.description),
                },
                locations,
            }
        })
        .collect();

    let has_errors = report
        .findings
        .iter()
        .any(|f| matches!(f.severity, Severity::Critical | Severity::High));

    SarifLog {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        version: "2.1.0",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifToolComponent {
                    name: "nucleus-audit",
                    semantic_version: env!("CARGO_PKG_VERSION"),
                    information_uri: "https://github.com/coproduct-opensource/nucleus",
                    rules,
                },
            },
            results,
            invocations: vec![SarifInvocation {
                execution_successful: !has_errors,
            }],
        }],
    }
}

/// Map finding category to a human-readable description for the SARIF rule.
fn category_description(category: &str) -> String {
    match category {
        "credentials" => "Credential exposure in agent configuration".to_string(),
        "trifecta" => {
            "Lethal trifecta risk: private data + untrusted content + exfiltration".to_string()
        }
        "network" => "Network security posture issue".to_string(),
        "isolation" => "Insufficient isolation for agent execution".to_string(),
        "execution" => "Dangerous command execution pattern".to_string(),
        "supply_chain" => "Supply chain risk from unverified packages".to_string(),
        "surface_area" => "Excessive attack surface from tool configuration".to_string(),
        "policy" => "Policy configuration issue".to_string(),
        "budget" => "Missing or excessive budget limits".to_string(),
        "timeout" => "Missing or excessive timeout configuration".to_string(),
        other if other.starts_with("mcp_") => {
            format!("MCP server {} access risk", &other["mcp_".len()..],)
        }
        other => format!("Security finding: {}", other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Finding, ScanReport, Severity};

    fn make_report(findings: Vec<Finding>, sources: Vec<String>) -> ScanReport {
        ScanReport {
            findings,
            scanned_sources: sources,
            ..ScanReport::default()
        }
    }

    #[test]
    fn test_empty_report_produces_valid_sarif() {
        let report = make_report(vec![], vec![]);
        let sarif = scan_report_to_sarif(&report);

        assert_eq!(sarif.version, "2.1.0");
        assert_eq!(sarif.runs.len(), 1);
        assert!(sarif.runs[0].results.is_empty());
        assert!(sarif.runs[0].tool.driver.rules.is_empty());
        assert!(sarif.runs[0].invocations[0].execution_successful);
    }

    #[test]
    fn test_findings_map_to_results() {
        let report = make_report(
            vec![
                Finding {
                    severity: Severity::High,
                    category: "credentials".to_string(),
                    title: "Plaintext API key".to_string(),
                    description: "Found hardcoded credential".to_string(),
                },
                Finding {
                    severity: Severity::Medium,
                    category: "network".to_string(),
                    title: "Open network".to_string(),
                    description: "No egress filtering".to_string(),
                },
            ],
            vec!["pod.yaml".to_string()],
        );
        let sarif = scan_report_to_sarif(&report);

        assert_eq!(sarif.runs[0].results.len(), 2);
        assert_eq!(sarif.runs[0].tool.driver.rules.len(), 2);

        // High severity → error
        assert_eq!(sarif.runs[0].results[0].level, "error");
        assert_eq!(sarif.runs[0].results[0].rule_id, "nucleus/credentials");

        // Medium severity → warning
        assert_eq!(sarif.runs[0].results[1].level, "warning");
        assert_eq!(sarif.runs[0].results[1].rule_id, "nucleus/network");

        // Single source → location on all results
        assert_eq!(sarif.runs[0].results[0].locations.len(), 1);
        assert_eq!(
            sarif.runs[0].results[0].locations[0]
                .physical_location
                .artifact_location
                .uri,
            "pod.yaml"
        );

        // Has errors → execution not successful
        assert!(!sarif.runs[0].invocations[0].execution_successful);
    }

    #[test]
    fn test_severity_mapping() {
        assert_eq!(severity_to_sarif_level(&Severity::Critical), "error");
        assert_eq!(severity_to_sarif_level(&Severity::High), "error");
        assert_eq!(severity_to_sarif_level(&Severity::Medium), "warning");
        assert_eq!(severity_to_sarif_level(&Severity::Low), "note");
        assert_eq!(severity_to_sarif_level(&Severity::Info), "note");
    }

    #[test]
    fn test_source_extraction_from_title() {
        let finding = Finding {
            severity: Severity::High,
            category: "credentials".to_string(),
            title: "[configs/mcp.json] Plaintext API key".to_string(),
            description: "desc".to_string(),
        };
        assert_eq!(
            extract_source_path(&finding),
            Some("configs/mcp.json".to_string())
        );

        let plain = Finding {
            severity: Severity::Low,
            category: "network".to_string(),
            title: "No brackets here".to_string(),
            description: "desc".to_string(),
        };
        assert_eq!(extract_source_path(&plain), None);
    }

    #[test]
    fn test_deduped_rules_for_same_category() {
        let report = make_report(
            vec![
                Finding {
                    severity: Severity::High,
                    category: "credentials".to_string(),
                    title: "Cred 1".to_string(),
                    description: "desc".to_string(),
                },
                Finding {
                    severity: Severity::High,
                    category: "credentials".to_string(),
                    title: "Cred 2".to_string(),
                    description: "desc".to_string(),
                },
            ],
            vec![],
        );
        let sarif = scan_report_to_sarif(&report);

        // Two results but only one rule
        assert_eq!(sarif.runs[0].results.len(), 2);
        assert_eq!(sarif.runs[0].tool.driver.rules.len(), 1);
    }

    #[test]
    fn test_sarif_json_roundtrip() {
        let report = make_report(
            vec![Finding {
                severity: Severity::Medium,
                category: "supply_chain".to_string(),
                title: "Unpinned package".to_string(),
                description: "desc".to_string(),
            }],
            vec!["mcp.json".to_string()],
        );
        let sarif = scan_report_to_sarif(&report);
        let json = serde_json::to_string_pretty(&sarif).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["version"], "2.1.0");
        assert_eq!(parsed["runs"][0]["tool"]["driver"]["name"], "nucleus-audit");
        assert_eq!(
            parsed["runs"][0]["results"][0]["ruleId"],
            "nucleus/supply_chain"
        );
        assert_eq!(parsed["runs"][0]["results"][0]["level"], "warning");
    }

    #[test]
    fn test_no_findings_means_successful() {
        let report = make_report(vec![], vec!["clean.yaml".to_string()]);
        let sarif = scan_report_to_sarif(&report);
        assert!(sarif.runs[0].invocations[0].execution_successful);
    }

    #[test]
    fn test_mcp_category_description() {
        assert!(category_description("mcp_database").contains("database"));
        assert!(category_description("mcp_vcs").contains("vcs"));
    }

    #[test]
    fn test_rule_name_formatting() {
        assert_eq!(rule_name_from_category("supply_chain"), "Supply Chain");
        assert_eq!(rule_name_from_category("credentials"), "Credentials");
        assert_eq!(rule_name_from_category("mcp_database"), "Mcp Database");
    }
}
