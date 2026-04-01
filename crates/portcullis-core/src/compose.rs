//! Declarative multi-compartment workflow orchestration — the "ifc-compose" format.
//!
//! This module provides a TOML-based declarative format for defining
//! multi-agent workflows where agents operate in distinct compartments
//! and hand off artifacts through IFC-verified data flows.
//!
//! Think of it as the docker-compose equivalent for compartmentalized
//! agent workflows: each agent runs in a named compartment with a policy
//! profile, and flows define what data can move between them.
//!
//! ## File location
//!
//! A compose file lives at `.nucleus/compose.toml` in the project root.
//!
//! ## Format
//!
//! ```toml
//! version = "1"
//!
//! [[agents]]
//! name = "researcher"
//! compartment = "research"
//! profile = "research-web"
//!
//! [[agents]]
//! name = "coder"
//! compartment = "draft"
//! profile = "codegen"
//!
//! [agents.env]
//! LANG = "rust"
//!
//! [[agents]]
//! name = "tester"
//! compartment = "execute"
//! profile = "test-runner"
//!
//! [[flows]]
//! from = "researcher"
//! to = "coder"
//! artifacts = ["research_notes", "api_docs"]
//! requires_declassification = false
//!
//! [[flows]]
//! from = "coder"
//! to = "tester"
//! artifacts = ["source_code", "test_plan"]
//! requires_declassification = false
//! ```

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

/// Errors from parsing or validating a compose workflow.
#[derive(Debug)]
pub enum ComposeError {
    /// TOML parse failure.
    ParseError(String),
    /// I/O error reading the file.
    IoError(std::io::Error),
    /// Unsupported version string.
    UnsupportedVersion(String),
    /// A flow references an agent name that is not defined.
    UndefinedAgent {
        flow_field: &'static str,
        agent: String,
    },
    /// A flow has the same agent as both source and destination.
    SelfFlow { agent: String },
    /// Duplicate agent name.
    DuplicateAgent(String),
    /// An agent references a compartment that is not known.
    UndefinedCompartment { agent: String, compartment: String },
    /// No agents defined.
    Empty,
}

impl std::fmt::Display for ComposeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParseError(msg) => write!(f, "TOML parse error: {msg}"),
            Self::IoError(e) => write!(f, "I/O error: {e}"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported version: {v}"),
            Self::UndefinedAgent { flow_field, agent } => {
                write!(
                    f,
                    "flow `{flow_field}` references undefined agent '{agent}'"
                )
            }
            Self::SelfFlow { agent } => {
                write!(f, "flow from agent '{agent}' to itself is not allowed")
            }
            Self::DuplicateAgent(name) => write!(f, "duplicate agent name: '{name}'"),
            Self::UndefinedCompartment { agent, compartment } => {
                write!(
                    f,
                    "agent '{agent}' references undefined compartment '{compartment}'"
                )
            }
            Self::Empty => write!(f, "compose workflow defines no agents"),
        }
    }
}

impl std::error::Error for ComposeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IoError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ComposeError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

/// Definition of a single agent within a compose workflow.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgentDef {
    /// Unique name for this agent (e.g. "researcher", "coder").
    pub name: String,

    /// The compartment this agent operates within. Must correspond to
    /// a compartment defined in the project's Compartmentfile.
    pub compartment: String,

    /// Optional policy profile name to apply (e.g. "research-web", "codegen").
    #[serde(default)]
    pub profile: Option<String>,

    /// Environment variables passed to this agent's execution context.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

/// Definition of a data flow between two agents.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FlowDef {
    /// Source agent name.
    pub from: String,

    /// Destination agent name.
    pub to: String,

    /// Artifact types that may flow between these agents.
    /// An empty list means no artifacts can flow (the flow exists
    /// only to express ordering/dependency).
    #[serde(default)]
    pub artifacts: Vec<String>,

    /// Whether this flow requires explicit declassification before
    /// data can cross the compartment boundary. When `true`, the
    /// runtime must verify that a declassification receipt exists
    /// before allowing the transfer.
    #[serde(default)]
    pub requires_declassification: bool,
}

/// A parsed multi-compartment compose workflow.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ComposeWorkflow {
    /// Format version (currently only "1" is supported).
    pub version: String,

    /// Agent definitions. Each agent runs in a named compartment.
    #[serde(default)]
    pub agents: Vec<AgentDef>,

    /// Data flow definitions between agents.
    #[serde(default)]
    pub flows: Vec<FlowDef>,
}

impl ComposeWorkflow {
    /// The default file path relative to the project root.
    pub const DEFAULT_PATH: &'static str = ".nucleus/compose.toml";

    /// Parse a compose workflow from a TOML string.
    pub fn parse(toml_str: &str) -> Result<Self, ComposeError> {
        let workflow: ComposeWorkflow =
            toml::from_str(toml_str).map_err(|e| ComposeError::ParseError(e.to_string()))?;

        if workflow.version != "1" {
            return Err(ComposeError::UnsupportedVersion(workflow.version));
        }

        Ok(workflow)
    }

    /// Validate the workflow for internal consistency.
    ///
    /// Checks:
    /// - At least one agent is defined
    /// - No duplicate agent names
    /// - All flow `from`/`to` references point to defined agents
    /// - No self-flows (from == to)
    /// - If `known_compartments` is provided, all agent compartments exist in it
    pub fn validate(
        &self,
        known_compartments: Option<&HashSet<String>>,
    ) -> Result<(), ComposeError> {
        if self.agents.is_empty() {
            return Err(ComposeError::Empty);
        }

        // Check for duplicate agent names.
        let mut seen = HashSet::new();
        for agent in &self.agents {
            if !seen.insert(&agent.name) {
                return Err(ComposeError::DuplicateAgent(agent.name.clone()));
            }
        }

        // Validate compartment references if known compartments are provided.
        if let Some(compartments) = known_compartments {
            for agent in &self.agents {
                if !compartments.contains(&agent.compartment) {
                    return Err(ComposeError::UndefinedCompartment {
                        agent: agent.name.clone(),
                        compartment: agent.compartment.clone(),
                    });
                }
            }
        }

        // Validate flow references.
        let agent_names: HashSet<&str> = self.agents.iter().map(|a| a.name.as_str()).collect();

        for flow in &self.flows {
            if flow.from == flow.to {
                return Err(ComposeError::SelfFlow {
                    agent: flow.from.clone(),
                });
            }
            if !agent_names.contains(flow.from.as_str()) {
                return Err(ComposeError::UndefinedAgent {
                    flow_field: "from",
                    agent: flow.from.clone(),
                });
            }
            if !agent_names.contains(flow.to.as_str()) {
                return Err(ComposeError::UndefinedAgent {
                    flow_field: "to",
                    agent: flow.to.clone(),
                });
            }
        }

        Ok(())
    }

    /// Load a compose workflow from a directory, reading `.nucleus/compose.toml`.
    pub fn load_from_dir(dir: &Path) -> Result<Self, ComposeError> {
        let path = dir.join(Self::DEFAULT_PATH);
        let content = std::fs::read_to_string(&path)?;
        let workflow = Self::parse(&content)?;
        Ok(workflow)
    }

    /// Return the set of unique compartment names referenced by agents.
    pub fn compartment_names(&self) -> HashSet<String> {
        self.agents.iter().map(|a| a.compartment.clone()).collect()
    }

    /// Return the set of unique agent names.
    pub fn agent_names(&self) -> HashSet<String> {
        self.agents.iter().map(|a| a.name.clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASIC_WORKFLOW: &str = r#"
version = "1"

[[agents]]
name = "researcher"
compartment = "research"
profile = "research-web"

[[agents]]
name = "coder"
compartment = "draft"
profile = "codegen"

[agents.env]
LANG = "rust"

[[agents]]
name = "tester"
compartment = "execute"
profile = "test-runner"

[[flows]]
from = "researcher"
to = "coder"
artifacts = ["research_notes", "api_docs"]
requires_declassification = false

[[flows]]
from = "coder"
to = "tester"
artifacts = ["source_code", "test_plan"]
requires_declassification = true
"#;

    #[test]
    fn parse_basic_workflow() {
        let wf = ComposeWorkflow::parse(BASIC_WORKFLOW).unwrap();
        assert_eq!(wf.version, "1");
        assert_eq!(wf.agents.len(), 3);
        assert_eq!(wf.flows.len(), 2);

        // Check agent details.
        assert_eq!(wf.agents[0].name, "researcher");
        assert_eq!(wf.agents[0].compartment, "research");
        assert_eq!(wf.agents[0].profile.as_deref(), Some("research-web"));
        assert!(wf.agents[0].env.is_empty());

        assert_eq!(wf.agents[1].name, "coder");
        assert_eq!(wf.agents[1].env.get("LANG").unwrap(), "rust");

        // Check flow details.
        assert_eq!(wf.flows[0].from, "researcher");
        assert_eq!(wf.flows[0].to, "coder");
        assert_eq!(wf.flows[0].artifacts, vec!["research_notes", "api_docs"]);
        assert!(!wf.flows[0].requires_declassification);
        assert!(wf.flows[1].requires_declassification);
    }

    #[test]
    fn validate_basic_workflow() {
        let wf = ComposeWorkflow::parse(BASIC_WORKFLOW).unwrap();
        assert!(wf.validate(None).is_ok());
    }

    #[test]
    fn validate_with_known_compartments() {
        let wf = ComposeWorkflow::parse(BASIC_WORKFLOW).unwrap();
        let compartments: HashSet<String> = ["research", "draft", "execute"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(wf.validate(Some(&compartments)).is_ok());
    }

    #[test]
    fn validate_rejects_unknown_compartment() {
        let wf = ComposeWorkflow::parse(BASIC_WORKFLOW).unwrap();
        // Only "research" is known — "draft" and "execute" are missing.
        let compartments: HashSet<String> = ["research"].iter().map(|s| s.to_string()).collect();
        let err = wf.validate(Some(&compartments)).unwrap_err();
        assert!(
            matches!(err, ComposeError::UndefinedCompartment { ref agent, .. } if agent == "coder")
        );
    }

    #[test]
    fn validate_rejects_empty_agents() {
        let toml = r#"
version = "1"
agents = []
"#;
        let wf = ComposeWorkflow::parse(toml).unwrap();
        let err = wf.validate(None).unwrap_err();
        assert!(matches!(err, ComposeError::Empty));
    }

    #[test]
    fn validate_rejects_duplicate_agents() {
        let toml = r#"
version = "1"

[[agents]]
name = "researcher"
compartment = "research"

[[agents]]
name = "researcher"
compartment = "draft"
"#;
        let wf = ComposeWorkflow::parse(toml).unwrap();
        let err = wf.validate(None).unwrap_err();
        assert!(matches!(err, ComposeError::DuplicateAgent(ref n) if n == "researcher"));
    }

    #[test]
    fn validate_rejects_self_flow() {
        let toml = r#"
version = "1"

[[agents]]
name = "researcher"
compartment = "research"

[[flows]]
from = "researcher"
to = "researcher"
"#;
        let wf = ComposeWorkflow::parse(toml).unwrap();
        let err = wf.validate(None).unwrap_err();
        assert!(matches!(err, ComposeError::SelfFlow { ref agent } if agent == "researcher"));
    }

    #[test]
    fn validate_rejects_undefined_flow_source() {
        let toml = r#"
version = "1"

[[agents]]
name = "coder"
compartment = "draft"

[[flows]]
from = "ghost"
to = "coder"
"#;
        let wf = ComposeWorkflow::parse(toml).unwrap();
        let err = wf.validate(None).unwrap_err();
        assert!(
            matches!(err, ComposeError::UndefinedAgent { flow_field: "from", ref agent } if agent == "ghost")
        );
    }

    #[test]
    fn validate_rejects_undefined_flow_target() {
        let toml = r#"
version = "1"

[[agents]]
name = "coder"
compartment = "draft"

[[flows]]
from = "coder"
to = "ghost"
"#;
        let wf = ComposeWorkflow::parse(toml).unwrap();
        let err = wf.validate(None).unwrap_err();
        assert!(
            matches!(err, ComposeError::UndefinedAgent { flow_field: "to", ref agent } if agent == "ghost")
        );
    }

    #[test]
    fn parse_rejects_unsupported_version() {
        let toml = r#"
version = "99"

[[agents]]
name = "x"
compartment = "y"
"#;
        let err = ComposeWorkflow::parse(toml).unwrap_err();
        assert!(matches!(err, ComposeError::UnsupportedVersion(ref v) if v == "99"));
    }

    #[test]
    fn parse_minimal_workflow() {
        let toml = r#"
version = "1"

[[agents]]
name = "solo"
compartment = "research"
"#;
        let wf = ComposeWorkflow::parse(toml).unwrap();
        assert_eq!(wf.agents.len(), 1);
        assert!(wf.flows.is_empty());
        assert!(wf.agents[0].profile.is_none());
        assert!(wf.agents[0].env.is_empty());
        assert!(wf.validate(None).is_ok());
    }

    #[test]
    fn compartment_names_and_agent_names() {
        let wf = ComposeWorkflow::parse(BASIC_WORKFLOW).unwrap();
        let compartments = wf.compartment_names();
        assert!(compartments.contains("research"));
        assert!(compartments.contains("draft"));
        assert!(compartments.contains("execute"));
        assert_eq!(compartments.len(), 3);

        let agents = wf.agent_names();
        assert!(agents.contains("researcher"));
        assert!(agents.contains("coder"));
        assert!(agents.contains("tester"));
        assert_eq!(agents.len(), 3);
    }

    #[test]
    fn load_from_dir_not_found() {
        let err = ComposeWorkflow::load_from_dir(Path::new("/nonexistent")).unwrap_err();
        assert!(matches!(err, ComposeError::IoError(_)));
    }

    #[test]
    fn load_from_dir_roundtrip() {
        let dir = std::env::temp_dir().join("nucleus_compose_test");
        let nucleus_dir = dir.join(".nucleus");
        std::fs::create_dir_all(&nucleus_dir).unwrap();
        std::fs::write(nucleus_dir.join("compose.toml"), BASIC_WORKFLOW).unwrap();

        let wf = ComposeWorkflow::load_from_dir(&dir).unwrap();
        assert_eq!(wf.agents.len(), 3);
        assert!(wf.validate(None).is_ok());

        // Clean up.
        let _ = std::fs::remove_dir_all(&dir);
    }
}
