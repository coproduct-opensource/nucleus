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
    /// SARIF property bag carrying the information-flow-control (IFC) label.
    ///
    /// SARIF 2.1.0 permits a free-form `properties` object on any node
    /// (§3.8); GitHub Code Scanning renders `properties.tags` and ignores
    /// unknown keys safely. We use it to surface the capability/flow CLASS
    /// the finding concerns. See [`SarifPropertyBag`] for the honesty
    /// framing — this is NOT a machine-checked `flows_to` verdict.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SarifPropertyBag>,
}

/// SARIF property bag carrying an HONEST information-flow-control label.
///
/// IMPORTANT HONESTY FRAMING: the label here reflects *the capability/flow
/// CLASS this finding concerns, derived from the detected category*. It is
/// **NOT** a machine-checked `flows_to` lattice verdict and does **NOT**
/// imply runtime enforcement. The full source→sink reachability analysis
/// (the toxic-flow / "lethal trifecta" reachability graph) is a separate
/// pass in `portcullis-core::flow` and is not run by the static scanner.
///
/// In other words: this says "a credentials finding *concerns a confidential
/// source*", not "this credential *provably flows to* an exfiltration sink".
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SarifPropertyBag {
    /// The flow role this finding's category concerns.
    ///
    /// One of: `"source"`, `"sink"`, `"privileged-sink"`, `"transform"`,
    /// `"composite"`.
    pub flow_role: &'static str,

    /// A short, human-readable description of the IFC concern.
    pub concern: &'static str,

    /// A real [`portcullis_core::flow::NodeKind`] variant name, populated
    /// ONLY where a confident category→node-kind mapping exists. `None`
    /// when no confident mapping can be asserted (we do not fabricate one).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_kind: Option<&'static str>,

    /// Free-form tags. GitHub renders these in the Security tab. Always
    /// includes a label disclaiming that this is a capability-class label,
    /// not a proven flow verdict.
    pub tags: Vec<String>,
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
/// `nucleus/uninhabitable_state`, `nucleus/network`.
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
                help: Some(SarifMessage {
                    text: rule_help_text(&finding.category),
                }),
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
                properties: ifc_label_for_category(&finding.category),
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
        "uninhabitable_state" => {
            "Lethal uninhabitable_state risk: private data + untrusted content + exfiltration"
                .to_string()
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

/// Standard disclaimer tag appended to every IFC label so consumers of the
/// SARIF cannot mistake a capability-class label for a proven flow verdict.
const IFC_DISCLAIMER_TAG: &str = "ifc:capability-class-not-proven-flow";

/// Map a REAL scanner category to an HONEST IFC capability-class label.
///
/// Returns `None` for categories where no confident IFC mapping exists — we
/// deliberately do NOT fabricate a label in those cases (e.g. `policy`,
/// `timeout`, `surface_area`, `audit_integrity`, `safety_bypass`,
/// `permissions`, `isolation`, `supply_chain`, `hooks`).
///
/// HONESTY: `flow_role` describes the capability/flow CLASS the finding
/// concerns (derived purely from the detected category). It is NOT the output
/// of a `flows_to` lattice check. `node_kind`, where present, names a real
/// [`portcullis_core::flow::NodeKind`] variant that the category most closely
/// corresponds to — again, a classification, not a runtime-observed node.
pub fn ifc_label_for_category(category: &str) -> Option<SarifPropertyBag> {
    // Helper to build a tag vector with the mandatory disclaimer appended.
    fn tags(mut t: Vec<&str>) -> Vec<String> {
        t.push(IFC_DISCLAIMER_TAG);
        t.into_iter().map(str::to_string).collect()
    }

    let bag = match category {
        // ── Confidential SOURCES ────────────────────────────────────────
        // Credentials are secret-classified data at the source.
        "credentials" => SarifPropertyBag {
            flow_role: "source",
            concern: "confidential source: secret/credential material",
            node_kind: Some("Secret"),
            tags: tags(vec!["ifc:source", "ifc:confidential", "private-data"]),
        },
        // Database rows are internal-confidential, locally-trusted data.
        "database" => SarifPropertyBag {
            flow_role: "source",
            concern: "confidential source: database-resident data",
            node_kind: Some("DatabaseRow"),
            tags: tags(vec!["ifc:source", "ifc:confidential", "private-data"]),
        },

        // ── Untrusted (external/web) SOURCES ────────────────────────────
        // Browser/web content is adversarial-integrity, public-confidentiality.
        "browser" => SarifPropertyBag {
            flow_role: "source",
            concern: "untrusted source: web/browser content (adversarial integrity)",
            node_kind: Some("WebContent"),
            tags: tags(vec![
                "ifc:source",
                "ifc:untrusted-input",
                "untrusted-content",
            ]),
        },
        // Inbound communication content is external/untrusted input.
        "communication" => SarifPropertyBag {
            flow_role: "source",
            concern: "untrusted source: external communication content",
            node_kind: None, // no single confident NodeKind for arbitrary comms
            tags: tags(vec![
                "ifc:source",
                "ifc:untrusted-input",
                "untrusted-content",
            ]),
        },

        // ── Egress SINKS ────────────────────────────────────────────────
        // Network / exfiltration / cloud egress all reach an outbound sink.
        "network" | "exfiltration" | "cloud" => SarifPropertyBag {
            flow_role: "sink",
            concern: "egress sink: data may leave the trust boundary",
            node_kind: Some("OutboundAction"),
            tags: tags(vec!["ifc:sink", "ifc:egress", "exfiltration"]),
        },

        // ── Privileged-execution SINKS ──────────────────────────────────
        // Command/runtime execution is a privileged outbound action.
        "execution" | "runtime" => SarifPropertyBag {
            flow_role: "privileged-sink",
            concern: "privileged-exec sink: command/code execution",
            node_kind: Some("OutboundAction"),
            tags: tags(vec!["ifc:sink", "ifc:privileged", "ifc:execution"]),
        },
        // Version-control push (git push / open PR) is a privileged outbound
        // action that writes outside the local trust boundary.
        "vcs" => SarifPropertyBag {
            flow_role: "privileged-sink",
            concern: "privileged push sink: version-control write (push/PR)",
            node_kind: Some("OutboundAction"),
            tags: tags(vec!["ifc:sink", "ifc:privileged", "ifc:vcs"]),
        },

        // ── File source/sink (both directions) ──────────────────────────
        // Filesystem access can be a read (source) or a write (sink); we
        // classify it as a composite file source/sink and name the read
        // node kind, which is the most confident single mapping.
        "filesystem" => SarifPropertyBag {
            flow_role: "composite",
            concern: "file source/sink: filesystem read and/or write",
            node_kind: Some("FileRead"),
            tags: tags(vec!["ifc:source", "ifc:sink", "ifc:filesystem"]),
        },

        // ── The lethal trifecta (composite) ─────────────────────────────
        // An uninhabitable state co-locates private data + untrusted input +
        // an exfiltration path — the classic "lethal trifecta".
        "uninhabitable_state" => SarifPropertyBag {
            flow_role: "composite",
            concern: "lethal trifecta: private data + untrusted input + exfiltration path",
            node_kind: None, // composite of multiple node kinds — no single one is honest
            tags: tags(vec![
                "lethal-trifecta",
                "untrusted-input",
                "private-data",
                "exfiltration",
            ]),
        },

        // ── MCP servers (per the server's access class) ─────────────────
        // mcp_* categories name the access class of the MCP server. We map
        // the ones with a confident flow role; otherwise None.
        other if other.starts_with("mcp_") => {
            let server = &other["mcp_".len()..];
            match server {
                "database" => SarifPropertyBag {
                    flow_role: "source",
                    concern: "MCP confidential source: database server access",
                    node_kind: Some("DatabaseRow"),
                    tags: tags(vec![
                        "ifc:source",
                        "ifc:confidential",
                        "ifc:mcp",
                        "private-data",
                    ]),
                },
                "browser" | "fetch" | "web" => SarifPropertyBag {
                    flow_role: "source",
                    concern: "MCP untrusted source: web/fetch server (adversarial integrity)",
                    node_kind: Some("WebContent"),
                    tags: tags(vec![
                        "ifc:source",
                        "ifc:untrusted-input",
                        "ifc:mcp",
                        "untrusted-content",
                    ]),
                },
                "network" | "http" | "cloud" => SarifPropertyBag {
                    flow_role: "sink",
                    concern: "MCP egress sink: network/cloud server access",
                    node_kind: Some("OutboundAction"),
                    tags: tags(vec!["ifc:sink", "ifc:egress", "ifc:mcp", "exfiltration"]),
                },
                "vcs" | "git" | "github" => SarifPropertyBag {
                    flow_role: "privileged-sink",
                    concern: "MCP privileged push sink: version-control server",
                    node_kind: Some("OutboundAction"),
                    tags: tags(vec!["ifc:sink", "ifc:privileged", "ifc:mcp", "ifc:vcs"]),
                },
                "filesystem" | "fs" => SarifPropertyBag {
                    flow_role: "composite",
                    concern: "MCP file source/sink: filesystem server",
                    node_kind: Some("FileRead"),
                    tags: tags(vec!["ifc:source", "ifc:sink", "ifc:mcp", "ifc:filesystem"]),
                },
                // Unknown MCP server class — do not fabricate a flow role.
                _ => return None,
            }
        }

        // ── No confident mapping — DO NOT fabricate a label ─────────────
        // policy, timeout, surface_area, audit_integrity, safety_bypass,
        // permissions, isolation, supply_chain, hooks, budget, …
        _ => return None,
    };

    Some(bag)
}

/// Build the SARIF rule `help` text, including the IFC honesty disclaimer.
///
/// This text is shown in the GitHub Security tab rule description. It states
/// plainly that the attached IFC label is a CAPABILITY-CLASS label derived
/// from the detected category — NOT a machine-checked `flows_to` verdict and
/// NOT a claim of runtime enforcement.
fn rule_help_text(category: &str) -> String {
    let base = category_description(category);
    let ifc = match ifc_label_for_category(category) {
        Some(bag) => format!(
            " IFC label: flow role `{}` — {}.",
            bag.flow_role, bag.concern
        ),
        None => String::new(),
    };
    format!(
        "{base}{ifc} \
         NOTE: any attached IFC label reflects the capability/flow CLASS this \
         finding concerns, derived from the detected category. It is NOT a \
         machine-checked flows_to verdict and does NOT imply runtime \
         enforcement; full source→sink reachability (the toxic-flow graph) is \
         a separate analysis pass."
    )
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

    // ── Part A: IFC label tests ─────────────────────────────────────────

    #[test]
    fn test_credentials_finding_gets_source_role() {
        let report = make_report(
            vec![Finding {
                severity: Severity::High,
                category: "credentials".to_string(),
                title: "Plaintext API key".to_string(),
                description: "Found hardcoded credential".to_string(),
            }],
            vec!["pod.yaml".to_string()],
        );
        let sarif = scan_report_to_sarif(&report);
        let props = sarif.runs[0].results[0]
            .properties
            .as_ref()
            .expect("credentials finding must carry an IFC label");
        assert_eq!(props.flow_role, "source");
        assert_eq!(props.node_kind, Some("Secret"));
        // The disclaimer tag is always present.
        assert!(props.tags.iter().any(|t| t == IFC_DISCLAIMER_TAG));
    }

    #[test]
    fn test_network_and_exfiltration_findings_get_sink_role() {
        for cat in ["network", "exfiltration", "cloud"] {
            let report = make_report(
                vec![Finding {
                    severity: Severity::Medium,
                    category: cat.to_string(),
                    title: "egress".to_string(),
                    description: "desc".to_string(),
                }],
                vec![],
            );
            let sarif = scan_report_to_sarif(&report);
            let props = sarif.runs[0].results[0]
                .properties
                .as_ref()
                .unwrap_or_else(|| panic!("{cat} must carry an IFC label"));
            assert_eq!(props.flow_role, "sink", "category {cat}");
            assert_eq!(props.node_kind, Some("OutboundAction"), "category {cat}");
        }
    }

    #[test]
    fn test_execution_gets_privileged_sink() {
        let label = ifc_label_for_category("execution").unwrap();
        assert_eq!(label.flow_role, "privileged-sink");
        let label = ifc_label_for_category("vcs").unwrap();
        assert_eq!(label.flow_role, "privileged-sink");
    }

    #[test]
    fn test_uninhabitable_state_carries_lethal_trifecta_tags() {
        let report = make_report(
            vec![Finding {
                severity: Severity::Critical,
                category: "uninhabitable_state".to_string(),
                title: "Lethal trifecta".to_string(),
                description: "private data + untrusted + exfil".to_string(),
            }],
            vec![],
        );
        let sarif = scan_report_to_sarif(&report);
        let props = sarif.runs[0].results[0]
            .properties
            .as_ref()
            .expect("uninhabitable_state must carry an IFC label");
        assert_eq!(props.flow_role, "composite");
        for tag in [
            "lethal-trifecta",
            "untrusted-input",
            "private-data",
            "exfiltration",
        ] {
            assert!(
                props.tags.iter().any(|t| t == tag),
                "missing lethal-trifecta tag: {tag}"
            );
        }
        // No single honest NodeKind for the composite trifecta.
        assert_eq!(props.node_kind, None);
    }

    #[test]
    fn test_unmapped_category_yields_none_and_still_serializes() {
        // `policy` has no confident IFC mapping → properties: None.
        let report = make_report(
            vec![Finding {
                severity: Severity::Low,
                category: "policy".to_string(),
                title: "Policy nit".to_string(),
                description: "desc".to_string(),
            }],
            vec!["pod.yaml".to_string()],
        );
        let sarif = scan_report_to_sarif(&report);
        assert!(
            sarif.runs[0].results[0].properties.is_none(),
            "unmapped category must not fabricate an IFC label"
        );

        // The SARIF must still serialize to valid JSON, and the `properties`
        // key must be ABSENT (skip_serializing_if) on the unmapped result.
        let json = serde_json::to_string(&sarif).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["runs"][0]["results"][0].get("properties").is_none());
        assert_eq!(parsed["version"], "2.1.0");
    }

    #[test]
    fn test_ifc_label_serializes_camelcase_property_bag() {
        // A mapped finding must serialize a camelCase `properties` bag with
        // `flowRole`, `concern`, `nodeKind`, and `tags`.
        let report = make_report(
            vec![Finding {
                severity: Severity::High,
                category: "credentials".to_string(),
                title: "key".to_string(),
                description: "d".to_string(),
            }],
            vec![],
        );
        let sarif = scan_report_to_sarif(&report);
        let json = serde_json::to_string(&sarif).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let props = &parsed["runs"][0]["results"][0]["properties"];
        assert_eq!(props["flowRole"], "source");
        assert_eq!(props["nodeKind"], "Secret");
        assert!(props["concern"].is_string());
        assert!(props["tags"].is_array());
    }

    #[test]
    fn test_unknown_mcp_server_yields_no_label() {
        // A confident MCP mapping exists for known classes...
        assert!(ifc_label_for_category("mcp_database").is_some());
        assert!(ifc_label_for_category("mcp_filesystem").is_some());
        // ...but an unknown MCP server class must NOT fabricate a label.
        assert!(ifc_label_for_category("mcp_quux").is_none());
    }

    #[test]
    fn test_help_text_carries_honesty_disclaimer() {
        let help = rule_help_text("credentials");
        assert!(help.contains("capability/flow CLASS"));
        assert!(help.contains("NOT a machine-checked flows_to verdict"));
        // Unmapped categories still get the disclaimer (no IFC sentence,
        // but the NOTE is always present).
        let help_none = rule_help_text("policy");
        assert!(help_none.contains("NOT a machine-checked flows_to verdict"));
    }
}
