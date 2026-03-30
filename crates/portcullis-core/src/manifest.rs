//! Tool manifest schema and admission control for the Flow Kernel.
//!
//! Every MCP tool declares its security-relevant properties in a manifest.
//! Admission control rejects tools whose manifests permit unsafe flows
//! (e.g., remote instruction fetch from unlabeled origins).
//!
//! **Current status**: types + admission rules + tests. Integration with
//! the tool schema registry (`portcullis/src/tool_schema.rs`) is planned.

use crate::{AuthorityLevel, ConfLevel, IntegLevel, Operation};

// ═══════════════════════════════════════════════════════════════════════════
// Manifest types
// ═══════════════════════════════════════════════════════════════════════════

/// Where a tool can fetch instructions at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstructionSource {
    /// Instructions come only from the tool's static configuration.
    Static,
    /// Instructions come from the user's prompt (direct).
    UserPrompt,
    /// Instructions fetched from a remote URL at runtime.
    RemoteUrl,
    /// Instructions come from another tool's output (transitive).
    TransitiveTool,
    /// Source is unknown or undeclared.
    Unlabeled,
}

/// What kinds of sinks a tool's output may reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkClass {
    /// Output stays within the agent's working memory.
    LocalMemory,
    /// Output is written to the local filesystem.
    LocalFile,
    /// Output is sent to an external network endpoint.
    ExternalNetwork,
    /// Output is posted to a version control system (git, PR).
    VersionControl,
    /// Output reaches a human via UI/notification.
    HumanVisible,
}

/// Maximum number of operations, instruction sources, and sinks per manifest.
pub const MAX_MANIFEST_OPS: usize = 12;
pub const MAX_MANIFEST_SOURCES: usize = 5;
pub const MAX_MANIFEST_SINKS: usize = 5;

/// Tool manifest — security-relevant declarations for an MCP tool.
///
/// Every tool MUST declare what capabilities it uses, where it gets
/// instructions, and what sinks its output can reach. Admission control
/// rejects tools with unsafe combinations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolManifest {
    /// Tool name (must match the MCP tool name exactly).
    pub name: [u8; 64],
    pub name_len: u8,

    /// Operations this tool performs.
    pub capabilities: [Option<Operation>; MAX_MANIFEST_OPS],

    /// Does this tool fetch data from external URLs at runtime?
    pub remote_fetch: bool,

    /// Where can instructions come from that influence this tool's behavior?
    pub instruction_sources: [Option<InstructionSource>; MAX_MANIFEST_SOURCES],

    /// What kinds of sinks can this tool's output reach?
    pub admissible_sinks: [Option<SinkClass>; MAX_MANIFEST_SINKS],

    /// Maximum confidentiality level this tool handles.
    pub max_confidentiality: ConfLevel,

    /// Minimum integrity level this tool guarantees for its output.
    pub output_integrity: IntegLevel,

    /// Authority level this tool's output carries.
    pub output_authority: AuthorityLevel,

    /// Schema hash (SHA-256 of name + description + parameters).
    pub schema_hash: [u8; 32],
}

// ═══════════════════════════════════════════════════════════════════════════
// Admission control
// ═══════════════════════════════════════════════════════════════════════════

/// Why a tool manifest was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionDenyReason {
    /// Tool fetches remote URLs AND has unlabeled instruction sources.
    RemoteFetchUnlabeledInstructions,
    /// Tool has external network sinks without declaring remote_fetch.
    UndeclaredExternalSink,
    /// Tool claims Trusted output integrity but fetches from remote URLs.
    TrustedOutputFromRemote,
    /// Tool claims Directive authority but has transitive instruction sources.
    DirectiveFromTransitive,
    /// Tool has no declared capabilities.
    EmptyCapabilities,
}

/// Result of admission control check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionVerdict {
    /// Tool is admitted.
    Admit,
    /// Tool is rejected.
    Reject(AdmissionDenyReason),
}

/// Check if a tool manifest should be admitted.
///
/// Rejects tools with unsafe combinations of remote fetch, instruction
/// sources, output sinks, and declared security levels.
pub fn check_admission(manifest: &ToolManifest) -> AdmissionVerdict {
    // Rule 1: Must declare at least one capability
    let has_capabilities = manifest.capabilities.iter().any(|c| c.is_some());
    if !has_capabilities {
        return AdmissionVerdict::Reject(AdmissionDenyReason::EmptyCapabilities);
    }

    // Rule 2: Remote fetch + unlabeled instruction sources = reject
    if manifest.remote_fetch {
        let has_unlabeled = manifest
            .instruction_sources
            .iter()
            .any(|s| matches!(s, Some(InstructionSource::Unlabeled)));
        if has_unlabeled {
            return AdmissionVerdict::Reject(AdmissionDenyReason::RemoteFetchUnlabeledInstructions);
        }
    }

    // Rule 3: External network sinks require remote_fetch declaration
    let has_external_sink = manifest
        .admissible_sinks
        .iter()
        .any(|s| matches!(s, Some(SinkClass::ExternalNetwork)));
    if has_external_sink && !manifest.remote_fetch {
        return AdmissionVerdict::Reject(AdmissionDenyReason::UndeclaredExternalSink);
    }

    // Rule 4: Trusted output cannot come from remote-fetching tools
    if manifest.remote_fetch && manifest.output_integrity == IntegLevel::Trusted {
        return AdmissionVerdict::Reject(AdmissionDenyReason::TrustedOutputFromRemote);
    }

    // Rule 5: Directive authority cannot come from transitive instruction sources
    let has_transitive = manifest
        .instruction_sources
        .iter()
        .any(|s| matches!(s, Some(InstructionSource::TransitiveTool)));
    if has_transitive && manifest.output_authority == AuthorityLevel::Directive {
        return AdmissionVerdict::Reject(AdmissionDenyReason::DirectiveFromTransitive);
    }

    AdmissionVerdict::Admit
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn base_manifest() -> ToolManifest {
        let mut m = ToolManifest {
            name: [0; 64],
            name_len: 9,
            capabilities: [None; MAX_MANIFEST_OPS],
            remote_fetch: false,
            instruction_sources: [None; MAX_MANIFEST_SOURCES],
            admissible_sinks: [None; MAX_MANIFEST_SINKS],
            max_confidentiality: ConfLevel::Internal,
            output_integrity: IntegLevel::Untrusted,
            output_authority: AuthorityLevel::Informational,
            schema_hash: [0; 32],
        };
        m.name[..9].copy_from_slice(b"read_file");
        m.capabilities[0] = Some(Operation::ReadFiles);
        m.instruction_sources[0] = Some(InstructionSource::Static);
        m.admissible_sinks[0] = Some(SinkClass::LocalMemory);
        m
    }

    #[test]
    fn admits_safe_read_tool() {
        let m = base_manifest();
        assert_eq!(check_admission(&m), AdmissionVerdict::Admit);
    }

    #[test]
    fn rejects_empty_capabilities() {
        let mut m = base_manifest();
        m.capabilities = [None; MAX_MANIFEST_OPS];
        assert_eq!(
            check_admission(&m),
            AdmissionVerdict::Reject(AdmissionDenyReason::EmptyCapabilities)
        );
    }

    #[test]
    fn rejects_remote_fetch_with_unlabeled_sources() {
        let mut m = base_manifest();
        m.remote_fetch = true;
        m.instruction_sources[1] = Some(InstructionSource::Unlabeled);
        assert_eq!(
            check_admission(&m),
            AdmissionVerdict::Reject(AdmissionDenyReason::RemoteFetchUnlabeledInstructions)
        );
    }

    #[test]
    fn rejects_undeclared_external_sink() {
        let mut m = base_manifest();
        m.admissible_sinks[1] = Some(SinkClass::ExternalNetwork);
        // remote_fetch is false — undeclared
        assert_eq!(
            check_admission(&m),
            AdmissionVerdict::Reject(AdmissionDenyReason::UndeclaredExternalSink)
        );
    }

    #[test]
    fn rejects_trusted_output_from_remote() {
        let mut m = base_manifest();
        m.remote_fetch = true;
        m.output_integrity = IntegLevel::Trusted;
        assert_eq!(
            check_admission(&m),
            AdmissionVerdict::Reject(AdmissionDenyReason::TrustedOutputFromRemote)
        );
    }

    #[test]
    fn rejects_directive_from_transitive() {
        let mut m = base_manifest();
        m.instruction_sources[1] = Some(InstructionSource::TransitiveTool);
        m.output_authority = AuthorityLevel::Directive;
        assert_eq!(
            check_admission(&m),
            AdmissionVerdict::Reject(AdmissionDenyReason::DirectiveFromTransitive)
        );
    }

    #[test]
    fn admits_remote_fetch_with_labeled_sources() {
        let mut m = base_manifest();
        m.remote_fetch = true;
        m.admissible_sinks[1] = Some(SinkClass::ExternalNetwork);
        // Instruction sources are all Static (labeled) — no Unlabeled
        assert_eq!(check_admission(&m), AdmissionVerdict::Admit);
    }

    // ── Exploit scenario: tool-description poisoning ─────────────────

    #[test]
    fn rejects_poisoned_tool_manifest() {
        // A malicious MCP server declares a tool that:
        // - Fetches instructions from remote URLs
        // - Has unlabeled instruction sources (poison vector)
        // - Claims Directive authority (instruction escalation)
        let mut m = base_manifest();
        m.remote_fetch = true;
        m.instruction_sources[1] = Some(InstructionSource::RemoteUrl);
        m.instruction_sources[2] = Some(InstructionSource::Unlabeled);
        m.output_authority = AuthorityLevel::Directive;

        // REJECTED: remote fetch + unlabeled instructions
        assert_eq!(
            check_admission(&m),
            AdmissionVerdict::Reject(AdmissionDenyReason::RemoteFetchUnlabeledInstructions)
        );
    }
}
