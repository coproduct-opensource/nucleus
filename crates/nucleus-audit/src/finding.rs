//! Shared types for security scan findings.

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical = 0,
    High = 1,
    Medium = 2,
    Low = 3,
    Info = 4,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub category: String,
    pub title: String,
    pub description: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pod_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_profile: Option<String>,
    pub trifecta_risk: String,
    pub trifecta_enforced: bool,
    pub permission_surface: PermissionSurface,
    pub network_posture: String,
    pub isolation_level: String,
    pub has_credentials: bool,
    pub findings: Vec<Finding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scanned_sources: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_metrics: Option<RuntimeMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claude_settings_summary: Option<ClaudeSettingsSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_config_summary: Option<McpConfigSummary>,
}

impl Default for ScanReport {
    fn default() -> Self {
        Self {
            pod_name: None,
            policy_profile: None,
            trifecta_risk: "None".to_string(),
            trifecta_enforced: false,
            permission_surface: PermissionSurface::default(),
            network_posture: "unspecified".to_string(),
            isolation_level: "none".to_string(),
            has_credentials: false,
            findings: Vec::new(),
            scanned_sources: Vec::new(),
            runtime_metrics: None,
            claude_settings_summary: None,
            mcp_config_summary: None,
        }
    }
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct PermissionSurface {
    pub total_capabilities: usize,
    pub always_allowed: Vec<String>,
    pub low_risk: Vec<String>,
    pub never: Vec<String>,
    pub approval_required: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RuntimeMetrics {
    pub total_entries: usize,
    pub chain_valid: bool,
    pub deviations: usize,
    pub trifecta_completions: usize,
    pub blocks: usize,
    pub identities: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ClaudeSettingsSummary {
    pub total_allow_rules: usize,
    pub total_deny_rules: usize,
    pub total_ask_rules: usize,
    pub mcp_server_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox_enabled: Option<bool>,
    pub safety_bypasses: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct McpConfigSummary {
    pub server_count: usize,
    pub command_servers: usize,
    pub http_servers: usize,
    pub servers_with_credentials: usize,
}
