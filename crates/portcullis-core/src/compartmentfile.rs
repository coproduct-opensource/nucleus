//! Declarative compartment definitions — the "Compartmentfile" format.
//!
//! This module provides a TOML-based declarative format for defining agent
//! compartments, replacing the hardcoded 4-variant `Compartment` enum with
//! user-defined compartments. Think of it as the Dockerfile equivalent for
//! agent privilege boundaries.
//!
//! ## File location
//!
//! A `Compartmentfile` lives at `.nucleus/Compartmentfile` in the project root.
//!
//! ## Format
//!
//! ```toml
//! version = "1"
//!
//! [[compartments]]
//! name = "research"
//! capabilities.read_files = "always"
//! capabilities.web_fetch = "always"
//! allowed_sinks = ["workspace_write"]
//! requires_trusted_ancestry = false
//!
//! [[compartments]]
//! name = "draft"
//! base = "research"
//! capabilities.write_files = "always"
//! capabilities.edit_files = "always"
//! denied_sinks = ["http_egress"]
//!
//! [[compartments]]
//! name = "execute"
//! base = "draft"
//! capabilities.run_bash = "low_risk"
//! capabilities.git_commit = "always"
//! requires_trusted_ancestry = true
//! max_delegation_depth = 2
//!
//! [[compartments]]
//! name = "breakglass"
//! base = "execute"
//! capabilities.git_push = "always"
//! capabilities.create_pr = "always"
//! requires_trusted_ancestry = true
//! ```
//!
//! ## Ordering
//!
//! Compartments are ordered by declaration — the first is least privileged.
//! A compartment's `base` must refer to a previously declared compartment
//! (enforcing a DAG with no circular references).

use crate::{CapabilityLattice, CapabilityLevel, SinkClass};
use std::collections::HashSet;
use std::path::Path;

/// Errors from parsing or validating a Compartmentfile.
#[derive(Debug)]
pub enum CompartmentfileError {
    /// TOML parse failure.
    ParseError(String),
    /// I/O error reading the file.
    IoError(std::io::Error),
    /// Unsupported version string.
    UnsupportedVersion(String),
    /// A `base` reference points to an undefined compartment.
    UndefinedBase { compartment: String, base: String },
    /// A `base` reference points to a compartment declared after this one
    /// (forward reference), which would create ordering ambiguity.
    ForwardBaseReference { compartment: String, base: String },
    /// Duplicate compartment name.
    DuplicateName(String),
    /// No compartments defined.
    Empty,
}

impl std::fmt::Display for CompartmentfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParseError(msg) => write!(f, "TOML parse error: {msg}"),
            Self::IoError(e) => write!(f, "I/O error: {e}"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported version: {v}"),
            Self::UndefinedBase { compartment, base } => {
                write!(
                    f,
                    "compartment '{compartment}' references undefined base '{base}'"
                )
            }
            Self::ForwardBaseReference { compartment, base } => {
                write!(
                    f,
                    "compartment '{compartment}' references base '{base}' which is declared after it"
                )
            }
            Self::DuplicateName(name) => write!(f, "duplicate compartment name: '{name}'"),
            Self::Empty => write!(f, "Compartmentfile defines no compartments"),
        }
    }
}

impl std::error::Error for CompartmentfileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IoError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for CompartmentfileError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

/// A single compartment definition.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CompartmentDef {
    /// Unique name for this compartment (e.g. "research", "draft").
    pub name: String,

    /// Optional base compartment to inherit from. The base must be declared
    /// before this compartment in the file.
    #[serde(default)]
    pub base: Option<String>,

    /// Capability ceiling for this compartment. Fields not specified default
    /// to `Never` (or inherited from base if `base` is set).
    #[serde(default)]
    pub capabilities: CapabilityLattice,

    /// Sink classes explicitly allowed in this compartment.
    #[serde(default)]
    pub allowed_sinks: Vec<SinkClass>,

    /// Sink classes explicitly denied in this compartment.
    /// Denied sinks override allowed sinks.
    #[serde(default)]
    pub denied_sinks: Vec<SinkClass>,

    /// Allowed host patterns for network access (e.g. "*.example.com").
    #[serde(default)]
    pub allowed_hosts: Vec<String>,

    /// Maximum delegation depth for spawned child agents.
    #[serde(default)]
    pub max_delegation_depth: Option<u32>,

    /// Whether data flowing to privileged sinks must have verified
    /// trusted ancestry (no adversarial causal ancestors).
    #[serde(default)]
    pub requires_trusted_ancestry: bool,
}

impl CompartmentDef {
    /// Compute the effective set of allowed sinks: allowed minus denied.
    pub fn effective_sinks(&self) -> HashSet<SinkClass> {
        let denied: HashSet<SinkClass> = self.denied_sinks.iter().copied().collect();
        self.allowed_sinks
            .iter()
            .copied()
            .filter(|s| !denied.contains(s))
            .collect()
    }

    /// Resolve this compartment's capabilities against its base (if any).
    ///
    /// For each capability dimension, if this compartment's value is `Never`
    /// and a base is provided, inherit the base's value. This lets derived
    /// compartments only specify the capabilities they add or change.
    pub fn resolve_capabilities(&self, base: Option<&CompartmentDef>) -> CapabilityLattice {
        match base {
            None => self.capabilities.clone(),
            Some(base_def) => {
                let b = &base_def.capabilities;
                let s = &self.capabilities;
                CapabilityLattice {
                    read_files: inherit(s.read_files, b.read_files),
                    write_files: inherit(s.write_files, b.write_files),
                    edit_files: inherit(s.edit_files, b.edit_files),
                    run_bash: inherit(s.run_bash, b.run_bash),
                    glob_search: inherit(s.glob_search, b.glob_search),
                    grep_search: inherit(s.grep_search, b.grep_search),
                    web_search: inherit(s.web_search, b.web_search),
                    web_fetch: inherit(s.web_fetch, b.web_fetch),
                    git_commit: inherit(s.git_commit, b.git_commit),
                    git_push: inherit(s.git_push, b.git_push),
                    create_pr: inherit(s.create_pr, b.create_pr),
                    manage_pods: inherit(s.manage_pods, b.manage_pods),
                    spawn_agent: inherit(s.spawn_agent, b.spawn_agent),
                }
            }
        }
    }

    /// Resolve effective sinks by merging with base.
    ///
    /// Inherits allowed sinks from base, adds this compartment's allowed
    /// sinks, then subtracts this compartment's denied sinks.
    pub fn resolve_sinks(&self, base: Option<&CompartmentDef>) -> HashSet<SinkClass> {
        let mut sinks: HashSet<SinkClass> = match base {
            Some(base_def) => base_def.effective_sinks(),
            None => HashSet::new(),
        };
        for s in &self.allowed_sinks {
            sinks.insert(*s);
        }
        for s in &self.denied_sinks {
            sinks.remove(s);
        }
        sinks
    }
}

/// If `self_val` is `Never`, inherit from base; otherwise use self.
fn inherit(self_val: CapabilityLevel, base_val: CapabilityLevel) -> CapabilityLevel {
    if self_val == CapabilityLevel::Never {
        base_val
    } else {
        self_val
    }
}

/// Parsed Compartmentfile — a sequence of compartment definitions.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Compartmentfile {
    /// Format version (currently only "1" is supported).
    pub version: String,

    /// Ordered list of compartment definitions. First = least privileged.
    pub compartments: Vec<CompartmentDef>,
}

impl Compartmentfile {
    /// Parse a Compartmentfile from a TOML string.
    pub fn parse(toml_str: &str) -> Result<Self, CompartmentfileError> {
        let cf: Compartmentfile = toml::from_str(toml_str)
            .map_err(|e| CompartmentfileError::ParseError(e.to_string()))?;
        cf.validate()?;
        Ok(cf)
    }

    /// Load a Compartmentfile from a directory (reads `.nucleus/Compartmentfile`).
    pub fn load_from_dir(dir: &Path) -> Result<Self, CompartmentfileError> {
        let path = dir.join(".nucleus").join("Compartmentfile");
        let content = std::fs::read_to_string(&path)?;
        Self::parse(&content)
    }

    /// Validate the parsed Compartmentfile.
    ///
    /// Checks:
    /// - Version is supported
    /// - At least one compartment defined
    /// - No duplicate names
    /// - Base references point to previously declared compartments (no cycles)
    fn validate(&self) -> Result<(), CompartmentfileError> {
        if self.version != "1" {
            return Err(CompartmentfileError::UnsupportedVersion(
                self.version.clone(),
            ));
        }

        if self.compartments.is_empty() {
            return Err(CompartmentfileError::Empty);
        }

        let mut seen: Vec<&str> = Vec::new();
        let mut names: HashSet<&str> = HashSet::new();

        for def in &self.compartments {
            if !names.insert(&def.name) {
                return Err(CompartmentfileError::DuplicateName(def.name.clone()));
            }

            if let Some(ref base) = def.base
                && !names.contains(base.as_str())
            {
                // Is it defined later (forward reference) or not at all?
                let is_forward = self
                    .compartments
                    .iter()
                    .any(|c| c.name == *base && !seen.contains(&c.name.as_str()));
                if is_forward {
                    return Err(CompartmentfileError::ForwardBaseReference {
                        compartment: def.name.clone(),
                        base: base.clone(),
                    });
                }
                return Err(CompartmentfileError::UndefinedBase {
                    compartment: def.name.clone(),
                    base: base.clone(),
                });
            }

            seen.push(&def.name);
        }

        Ok(())
    }

    /// Look up a compartment definition by name.
    pub fn get(&self, name: &str) -> Option<&CompartmentDef> {
        self.compartments.iter().find(|c| c.name == name)
    }

    /// Resolve a compartment's full capabilities, walking the inheritance chain.
    pub fn resolve(&self, name: &str) -> Option<CapabilityLattice> {
        let def = self.get(name)?;
        let base = def.base.as_ref().and_then(|b| self.get(b));
        // For deep inheritance, walk the chain recursively
        let resolved_base = match (base, def.base.as_ref()) {
            (Some(base_def), Some(base_name)) => {
                let base_caps = self.resolve(base_name)?;
                Some(CompartmentDef {
                    capabilities: base_caps,
                    ..base_def.clone()
                })
            }
            _ => None,
        };
        Some(def.resolve_capabilities(resolved_base.as_ref()))
    }

    /// Return compartment names in declaration order (least to most privileged).
    pub fn names(&self) -> Vec<&str> {
        self.compartments.iter().map(|c| c.name.as_str()).collect()
    }
}

/// Generate the default Compartmentfile content matching the built-in
/// Research/Draft/Execute/Breakglass compartments.
pub fn default_compartmentfile() -> &'static str {
    r#"# Compartmentfile — declarative agent compartment definitions
# See: https://github.com/coproduct-opensource/nucleus
#
# Compartments are ordered least-privileged first. Each defines a capability
# ceiling that intersects with the session profile via meet().

version = "1"

# Research: read + web only. No writes, no execution.
[[compartments]]
name = "research"
requires_trusted_ancestry = false
allowed_sinks = ["workspace_write"]

[compartments.capabilities]
read_files = "always"
glob_search = "always"
grep_search = "always"
web_search = "always"
web_fetch = "always"

# Draft: read + write. No execution, no web.
[[compartments]]
name = "draft"
base = "research"
denied_sinks = ["http_egress"]

[compartments.capabilities]
read_files = "always"
write_files = "always"
edit_files = "always"
git_commit = "always"
web_search = "never"
web_fetch = "never"

# Execute: read + write + execution. No git push, no PR creation.
[[compartments]]
name = "execute"
base = "draft"
requires_trusted_ancestry = true
max_delegation_depth = 2
allowed_sinks = ["bash_exec", "git_commit"]

[compartments.capabilities]
read_files = "always"
write_files = "always"
edit_files = "always"
run_bash = "always"
git_commit = "always"
manage_pods = "always"
spawn_agent = "always"

# Breakglass: all capabilities. Enhanced audit trail.
[[compartments]]
name = "breakglass"
base = "execute"
requires_trusted_ancestry = true
allowed_sinks = ["git_push", "pr_comment_write", "http_egress"]

[compartments.capabilities]
read_files = "always"
write_files = "always"
edit_files = "always"
run_bash = "always"
glob_search = "always"
grep_search = "always"
web_search = "always"
web_fetch = "always"
git_commit = "always"
git_push = "always"
create_pr = "always"
manage_pods = "always"
spawn_agent = "always"
"#
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASIC_TOML: &str = r#"
version = "1"

[[compartments]]
name = "research"
requires_trusted_ancestry = false
allowed_sinks = ["workspace_write"]

[compartments.capabilities]
read_files = "always"
web_fetch = "always"

[[compartments]]
name = "draft"
base = "research"
denied_sinks = ["http_egress"]

[compartments.capabilities]
read_files = "always"
write_files = "always"
edit_files = "always"
"#;

    #[test]
    fn parse_basic_compartmentfile() {
        let cf = Compartmentfile::parse(BASIC_TOML).unwrap();
        assert_eq!(cf.version, "1");
        assert_eq!(cf.compartments.len(), 2);
        assert_eq!(cf.compartments[0].name, "research");
        assert_eq!(cf.compartments[1].name, "draft");
        assert_eq!(cf.compartments[1].base, Some("research".to_string()));
    }

    #[test]
    fn names_in_order() {
        let cf = Compartmentfile::parse(BASIC_TOML).unwrap();
        assert_eq!(cf.names(), vec!["research", "draft"]);
    }

    #[test]
    fn get_by_name() {
        let cf = Compartmentfile::parse(BASIC_TOML).unwrap();
        assert!(cf.get("research").is_some());
        assert!(cf.get("draft").is_some());
        assert!(cf.get("nonexistent").is_none());
    }

    #[test]
    fn effective_sinks_subtracts_denied() {
        let def = CompartmentDef {
            name: "test".to_string(),
            base: None,
            capabilities: CapabilityLattice::bottom(),
            allowed_sinks: vec![SinkClass::WorkspaceWrite, SinkClass::HTTPEgress],
            denied_sinks: vec![SinkClass::HTTPEgress],
            allowed_hosts: vec![],
            max_delegation_depth: None,
            requires_trusted_ancestry: false,
        };
        let effective = def.effective_sinks();
        assert!(effective.contains(&SinkClass::WorkspaceWrite));
        assert!(!effective.contains(&SinkClass::HTTPEgress));
        assert_eq!(effective.len(), 1);
    }

    #[test]
    fn inheritance_resolution() {
        let cf = Compartmentfile::parse(BASIC_TOML).unwrap();
        let resolved = cf.resolve("draft").unwrap();
        // Draft inherits read_files and web_fetch from research
        assert_eq!(resolved.read_files, CapabilityLevel::Always);
        assert_eq!(resolved.write_files, CapabilityLevel::Always);
        assert_eq!(resolved.edit_files, CapabilityLevel::Always);
        // web_fetch inherited from research base
        assert_eq!(resolved.web_fetch, CapabilityLevel::Always);
    }

    #[test]
    fn base_compartment_no_inheritance() {
        let cf = Compartmentfile::parse(BASIC_TOML).unwrap();
        let resolved = cf.resolve("research").unwrap();
        assert_eq!(resolved.read_files, CapabilityLevel::Always);
        assert_eq!(resolved.web_fetch, CapabilityLevel::Always);
        // Not specified -> Never
        assert_eq!(resolved.write_files, CapabilityLevel::Never);
        assert_eq!(resolved.run_bash, CapabilityLevel::Never);
    }

    #[test]
    fn reject_unsupported_version() {
        let toml = r#"
version = "2"
[[compartments]]
name = "test"
"#;
        let err = Compartmentfile::parse(toml).unwrap_err();
        assert!(matches!(err, CompartmentfileError::UnsupportedVersion(_)));
    }

    #[test]
    fn reject_empty_compartments() {
        let toml = r#"
version = "1"
compartments = []
"#;
        let err = Compartmentfile::parse(toml).unwrap_err();
        assert!(matches!(err, CompartmentfileError::Empty));
    }

    #[test]
    fn reject_duplicate_names() {
        let toml = r#"
version = "1"
[[compartments]]
name = "research"
[[compartments]]
name = "research"
"#;
        let err = Compartmentfile::parse(toml).unwrap_err();
        assert!(matches!(err, CompartmentfileError::DuplicateName(_)));
    }

    #[test]
    fn reject_undefined_base() {
        let toml = r#"
version = "1"
[[compartments]]
name = "draft"
base = "research"
"#;
        let err = Compartmentfile::parse(toml).unwrap_err();
        assert!(matches!(err, CompartmentfileError::UndefinedBase { .. }));
    }

    #[test]
    fn reject_forward_base_reference() {
        let toml = r#"
version = "1"
[[compartments]]
name = "draft"
base = "execute"
[[compartments]]
name = "execute"
"#;
        let err = Compartmentfile::parse(toml).unwrap_err();
        assert!(matches!(
            err,
            CompartmentfileError::ForwardBaseReference { .. }
        ));
    }

    #[test]
    fn resolve_sinks_with_inheritance() {
        let base_def = CompartmentDef {
            name: "base".to_string(),
            base: None,
            capabilities: CapabilityLattice::bottom(),
            allowed_sinks: vec![SinkClass::WorkspaceWrite, SinkClass::HTTPEgress],
            denied_sinks: vec![],
            allowed_hosts: vec![],
            max_delegation_depth: None,
            requires_trusted_ancestry: false,
        };

        let child_def = CompartmentDef {
            name: "child".to_string(),
            base: Some("base".to_string()),
            capabilities: CapabilityLattice::bottom(),
            allowed_sinks: vec![SinkClass::BashExec],
            denied_sinks: vec![SinkClass::HTTPEgress],
            allowed_hosts: vec![],
            max_delegation_depth: None,
            requires_trusted_ancestry: false,
        };

        let sinks = child_def.resolve_sinks(Some(&base_def));
        // Inherits WorkspaceWrite from base, adds BashExec, denies HTTPEgress
        assert!(sinks.contains(&SinkClass::WorkspaceWrite));
        assert!(sinks.contains(&SinkClass::BashExec));
        assert!(!sinks.contains(&SinkClass::HTTPEgress));
    }

    #[test]
    fn deep_inheritance_chain() {
        let toml = r#"
version = "1"

[[compartments]]
name = "level0"
[compartments.capabilities]
read_files = "always"

[[compartments]]
name = "level1"
base = "level0"
[compartments.capabilities]
write_files = "always"

[[compartments]]
name = "level2"
base = "level1"
[compartments.capabilities]
run_bash = "low_risk"
"#;
        let cf = Compartmentfile::parse(toml).unwrap();
        let resolved = cf.resolve("level2").unwrap();
        // Inherited from level0 via level1
        assert_eq!(resolved.read_files, CapabilityLevel::Always);
        // Inherited from level1
        assert_eq!(resolved.write_files, CapabilityLevel::Always);
        // Own capability
        assert_eq!(resolved.run_bash, CapabilityLevel::LowRisk);
        // Not set anywhere
        assert_eq!(resolved.git_push, CapabilityLevel::Never);
    }

    #[test]
    fn default_compartmentfile_parses() {
        let cf = Compartmentfile::parse(default_compartmentfile()).unwrap();
        assert_eq!(cf.compartments.len(), 4);
        assert_eq!(
            cf.names(),
            vec!["research", "draft", "execute", "breakglass"]
        );
    }

    #[test]
    fn default_breakglass_is_top() {
        let cf = Compartmentfile::parse(default_compartmentfile()).unwrap();
        let bg = cf.resolve("breakglass").unwrap();
        assert_eq!(bg, CapabilityLattice::top());
    }

    #[test]
    fn display_errors() {
        // Ensure Display impl covers all variants
        let errors = vec![
            CompartmentfileError::ParseError("bad".into()),
            CompartmentfileError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "gone",
            )),
            CompartmentfileError::UnsupportedVersion("99".into()),
            CompartmentfileError::UndefinedBase {
                compartment: "a".into(),
                base: "b".into(),
            },
            CompartmentfileError::ForwardBaseReference {
                compartment: "a".into(),
                base: "b".into(),
            },
            CompartmentfileError::DuplicateName("x".into()),
            CompartmentfileError::Empty,
        ];
        for e in &errors {
            let msg = format!("{e}");
            assert!(!msg.is_empty());
        }
    }

    #[test]
    fn load_from_dir_not_found() {
        let result = Compartmentfile::load_from_dir(Path::new("/tmp/nonexistent-nucleus-test"));
        assert!(result.is_err());
    }
}
