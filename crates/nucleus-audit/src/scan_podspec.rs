//! PodSpec security scanner.

use std::collections::HashSet;
use std::io::{BufRead, BufReader};
use std::path::Path;

use portcullis::CapabilityLevel;

use crate::finding::{Finding, PermissionSurface, RuntimeMetrics, ScanReport, Severity};
use crate::AuditError;

/// Signed line from FileAuditBackend.
#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)] // hmac used for deserialization matching
struct SignedLine {
    entry: serde_json::Value,
    hmac: String,
}

pub fn scan_pod_spec(
    pod_spec_path: &Path,
    audit_log_path: Option<&Path>,
) -> Result<ScanReport, AuditError> {
    let yaml = std::fs::read_to_string(pod_spec_path)?;
    let spec: nucleus_spec::PodSpec = serde_yaml::from_str(&yaml)
        .map_err(|e| AuditError::Backend(format!("failed to parse PodSpec: {}", e)))?;

    let lattice = spec
        .spec
        .resolve_policy()
        .map_err(|e| AuditError::Backend(format!("failed to resolve policy: {}", e)))?;

    let mut findings = Vec::new();

    // --- Policy analysis ---

    let policy_profile = match &spec.spec.policy {
        nucleus_spec::PolicySpec::Profile { name } => name.clone(),
        nucleus_spec::PolicySpec::Inline { .. } => "inline".to_string(),
    };

    let uninhabitable_state_config = portcullis::IncompatibilityConstraint::enforcing();
    let state_risk = uninhabitable_state_config.state_risk(&lattice.capabilities);
    let uninhabitable_state_enforced = lattice.is_uninhabitable_enforced();

    if !uninhabitable_state_enforced {
        findings.push(Finding {
            severity: Severity::Critical,
            category: "uninhabitable_state".to_string(),
            title: " UninhabitableState enforcement disabled".to_string(),
            description: "The uninhabitable_state constraint is disabled. An agent with \
                private data access + untrusted content + external communication can \
                exfiltrate data without approval gates."
                .to_string(),
        });
    }

    let uninhabitable_state_str = format!("{:?}", state_risk);
    if state_risk == portcullis::StateRisk::Uninhabitable && uninhabitable_state_enforced {
        findings.push(Finding {
            severity: Severity::Medium,
            category: "uninhabitable_state".to_string(),
            title: "Complete uninhabitable_state with enforcement".to_string(),
            description: "All three uninhabitable_state components are present. Enforcement is \
                enabled so exfiltration operations will require approval, but the \
                attack surface is maximal."
                .to_string(),
        });
    } else if state_risk == portcullis::StateRisk::Uninhabitable && !uninhabitable_state_enforced {
        findings.push(Finding {
            severity: Severity::Critical,
            category: "uninhabitable_state".to_string(),
            title: "Complete uninhabitable_state WITHOUT enforcement".to_string(),
            description: "All three uninhabitable_state components are present and enforcement \
                is disabled. This agent can read private data, fetch untrusted content, \
                and push to external systems without any approval gate."
                .to_string(),
        });
    }

    // --- Capability surface analysis ---

    let caps = &lattice.capabilities;
    let cap_fields: Vec<(&str, CapabilityLevel)> = vec![
        ("read_files", caps.read_files),
        ("write_files", caps.write_files),
        ("edit_files", caps.edit_files),
        ("run_bash", caps.run_bash),
        ("glob_search", caps.glob_search),
        ("grep_search", caps.grep_search),
        ("web_search", caps.web_search),
        ("web_fetch", caps.web_fetch),
        ("git_commit", caps.git_commit),
        ("git_push", caps.git_push),
        ("create_pr", caps.create_pr),
        ("manage_pods", caps.manage_pods),
    ];

    let always_allowed: Vec<String> = cap_fields
        .iter()
        .filter(|(_, l)| *l == CapabilityLevel::Always)
        .map(|(n, _)| n.to_string())
        .collect();
    let low_risk: Vec<String> = cap_fields
        .iter()
        .filter(|(_, l)| *l == CapabilityLevel::LowRisk)
        .map(|(n, _)| n.to_string())
        .collect();
    let never: Vec<String> = cap_fields
        .iter()
        .filter(|(_, l)| *l == CapabilityLevel::Never)
        .map(|(n, _)| n.to_string())
        .collect();

    let approval_required: Vec<String> = lattice
        .obligations
        .approvals
        .iter()
        .map(|op| format!("{:?}", op).to_lowercase())
        .collect();

    // High-risk capabilities without approval obligations
    let dangerous_ops = ["run_bash", "git_push", "create_pr", "manage_pods"];
    for (name, level) in &cap_fields {
        if dangerous_ops.contains(name) && *level >= CapabilityLevel::Always {
            let op_name = format!(
                "{:?}",
                match *name {
                    "run_bash" => portcullis::Operation::RunBash,
                    "git_push" => portcullis::Operation::GitPush,
                    "create_pr" => portcullis::Operation::CreatePr,
                    "manage_pods" => portcullis::Operation::ManagePods,
                    _ => continue,
                }
            );
            let has_approval = approval_required
                .iter()
                .any(|a| a == &op_name.to_lowercase());
            if !has_approval {
                findings.push(Finding {
                    severity: Severity::High,
                    category: "permissions".to_string(),
                    title: format!("{} is always-allowed without approval", name),
                    description: format!(
                        "The capability '{}' is set to Always with no approval \
                         obligation. Consider requiring human approval for this \
                         high-risk operation.",
                        name
                    ),
                });
            }
        }
    }

    if policy_profile == "permissive" {
        findings.push(Finding {
            severity: Severity::High,
            category: "policy".to_string(),
            title: "Permissive policy profile".to_string(),
            description: "The 'permissive' profile enables most capabilities. \
                Use a more restrictive profile like 'fix_issue' or 'code_review' \
                to enforce least privilege."
                .to_string(),
        });
    }

    // --- Network analysis ---

    let network_posture = match &spec.spec.network {
        Some(net) if !net.deny.is_empty() && net.dns_allow.is_empty() => "airgapped",
        Some(net) if !net.dns_allow.is_empty() => "filtered",
        Some(_) => "permissive",
        None => "unspecified",
    };

    if network_posture == "unspecified" {
        findings.push(Finding {
            severity: Severity::Medium,
            category: "network".to_string(),
            title: "No network policy specified".to_string(),
            description: "The PodSpec has no network configuration. The agent's \
                network access depends on the executor's defaults. Specify an \
                explicit NetworkSpec (deny_all, package_registries, or permissive)."
                .to_string(),
        });
    } else if network_posture == "permissive" {
        findings.push(Finding {
            severity: Severity::High,
            category: "network".to_string(),
            title: "Unrestricted network egress".to_string(),
            description: "The agent has unrestricted outbound network access. \
                This enables data exfiltration to arbitrary destinations. Use \
                NetworkSpec::package_registries() or deny_all() to restrict egress."
                .to_string(),
        });
    }

    // --- Isolation analysis ---

    let isolation_level = if spec.spec.image.is_some() {
        "firecracker"
    } else if spec.spec.seccomp.is_some() || spec.spec.cgroup.is_some() {
        "container"
    } else {
        "none"
    };

    if isolation_level == "none" {
        findings.push(Finding {
            severity: Severity::Medium,
            category: "isolation".to_string(),
            title: "No VM/container isolation configured".to_string(),
            description: "The PodSpec has no image, seccomp, or cgroup configuration. \
                The agent will run with host-level access unless the executor provides \
                isolation. Configure ImageSpec for Firecracker VM isolation."
                .to_string(),
        });
    }

    if let Some(nucleus_spec::SeccompSpec::Disabled) = &spec.spec.seccomp {
        findings.push(Finding {
            severity: Severity::High,
            category: "isolation".to_string(),
            title: "Seccomp disabled".to_string(),
            description: "Seccomp filtering is explicitly disabled. The agent process \
                can invoke any system call. Use Default or a custom filter."
                .to_string(),
        });
    }

    // --- Credential analysis ---

    let has_credentials = spec
        .spec
        .credentials
        .as_ref()
        .is_some_and(|c| !c.is_empty());
    if has_credentials {
        let creds = spec.spec.credentials.as_ref().unwrap();
        let dangerous_patterns = [
            "ROOT",
            "ADMIN",
            "MASTER",
            "PRIVATE_KEY",
            "AWS_SECRET",
            "DATABASE_URL",
        ];
        for key in creds.env.keys() {
            let upper = key.to_uppercase();
            for pattern in &dangerous_patterns {
                if upper.contains(pattern) {
                    findings.push(Finding {
                        severity: Severity::High,
                        category: "credentials".to_string(),
                        title: format!("High-privilege credential: {}", key),
                        description: format!(
                            "Credential '{}' matches pattern '{}'. Ensure this \
                             agent requires this level of access and that the \
                             credential is scoped to minimum privileges.",
                            key, pattern
                        ),
                    });
                }
            }
        }

        if creds.env.len() > 5 {
            findings.push(Finding {
                severity: Severity::Medium,
                category: "credentials".to_string(),
                title: format!("{} credentials injected", creds.env.len()),
                description: "A large number of credentials are injected. Each \
                    credential increases the blast radius of a compromised agent. \
                    Review whether all credentials are necessary."
                    .to_string(),
            });
        }
    }

    // --- Timeout analysis ---

    if spec.spec.timeout_seconds > 7200 {
        findings.push(Finding {
            severity: Severity::Low,
            category: "timeout".to_string(),
            title: format!("Long timeout: {}s", spec.spec.timeout_seconds),
            description: "Execution timeout exceeds 2 hours. Long-running agents \
                have more time to perform unauthorized actions if compromised. \
                Consider a shorter timeout with resume capability."
                .to_string(),
        });
    }

    // --- Runtime audit log analysis ---

    let runtime_metrics = if let Some(log_path) = audit_log_path {
        Some(analyze_audit_log(log_path, &mut findings)?)
    } else {
        None
    };

    // Sort findings by severity
    findings.sort_by(|a, b| a.severity.cmp(&b.severity));

    Ok(ScanReport {
        pod_name: spec.metadata.name,
        policy_profile: Some(policy_profile),
        state_risk: uninhabitable_state_str,
        uninhabitable_state_enforced,
        permission_surface: PermissionSurface {
            total_capabilities: cap_fields.len(),
            always_allowed,
            low_risk,
            never,
            approval_required,
        },
        network_posture: network_posture.to_string(),
        isolation_level: isolation_level.to_string(),
        has_credentials,
        findings,
        scanned_sources: Vec::new(),
        runtime_metrics,
        claude_settings_summary: None,
        mcp_config_summary: None,
    })
}

fn analyze_audit_log(
    log_path: &Path,
    findings: &mut Vec<Finding>,
) -> Result<RuntimeMetrics, AuditError> {
    let file = std::fs::File::open(log_path)?;
    let reader = BufReader::new(file);

    let log = portcullis::audit::AuditLog::in_memory();
    let mut identities: HashSet<String> = HashSet::new();
    let mut deviations = 0usize;
    let mut uninhabitable_completions = 0usize;
    let mut blocks = 0usize;
    let mut total = 0usize;

    for (idx, line) in reader.lines().enumerate() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let entry: portcullis::AuditEntry =
            if let Ok(signed) = serde_json::from_str::<SignedLine>(line) {
                serde_json::from_value(signed.entry).map_err(|source| AuditError::Json {
                    line: idx + 1,
                    source,
                })?
            } else {
                serde_json::from_str(line).map_err(|source| AuditError::Json {
                    line: idx + 1,
                    source,
                })?
            };

        identities.insert(entry.identity.clone());

        if entry.is_deviation() {
            deviations += 1;
        }
        if let Some(portcullis::StateRisk::Uninhabitable) = entry.uninhabitable_impact() {
            uninhabitable_completions += 1;
        }
        if matches!(
            &entry.event,
            portcullis::audit::PermissionEvent::ExecutionBlocked { .. }
        ) {
            blocks += 1;
        }

        log.record(entry);
        total += 1;
    }

    let chain_valid = log.verify_chain().is_ok();

    if !chain_valid {
        findings.push(Finding {
            severity: Severity::Critical,
            category: "audit_integrity".to_string(),
            title: "Audit log hash chain broken".to_string(),
            description: "The audit log's cryptographic hash chain is invalid. \
                This indicates tampering or corruption. The audit trail cannot \
                be trusted."
                .to_string(),
        });
    }

    if uninhabitable_completions > 0 {
        findings.push(Finding {
            severity: Severity::High,
            category: "runtime".to_string(),
            title: format!(
                "{} uninhabitable_state completion{} detected",
                uninhabitable_completions,
                if uninhabitable_completions == 1 {
                    ""
                } else {
                    "s"
                }
            ),
            description: format!(
                "The audit log contains {} events where all three uninhabitable_state \
                 components were active simultaneously. Review these events for \
                 potential data exfiltration.",
                uninhabitable_completions
            ),
        });
    }

    let deviation_rate = if total > 0 {
        deviations as f64 / total as f64
    } else {
        0.0
    };

    if deviation_rate > 0.1 {
        findings.push(Finding {
            severity: Severity::Medium,
            category: "runtime".to_string(),
            title: format!("High deviation rate: {:.1}%", deviation_rate * 100.0),
            description: format!(
                "{} of {} audit events ({:.1}%) are deviations from declared \
                 permissions. This suggests the declared policy is too restrictive \
                 (agents constantly escalating) or the agent is misbehaving.",
                deviations,
                total,
                deviation_rate * 100.0
            ),
        });
    }

    Ok(RuntimeMetrics {
        total_entries: total,
        chain_valid,
        deviations,
        uninhabitable_completions,
        blocks,
        identities: identities.len(),
    })
}
