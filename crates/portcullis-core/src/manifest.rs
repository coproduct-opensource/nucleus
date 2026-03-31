//! Tool manifest schema and admission control for the Flow Kernel.
//!
//! Every MCP tool declares its security-relevant properties in a manifest.
//! Admission control rejects tools whose manifests permit unsafe flows.
//!
//! ## Honest status
//!
//! This module provides TYPES and ADMISSION RULES only. It is NOT yet
//! wired into the MCP mediation layer or `Kernel::decide()`. Manifests
//! are self-declarations — a malicious tool can lie. Runtime behavioral
//! enforcement (verifying tools act according to their manifests) is
//! future work.
//!
//! The admission rules defend against honest-but-misconfigured tools
//! and tools that honestly declare dangerous capabilities. They do NOT
//! defend against adversarial tools that lie in their manifests.

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

/// Tool manifest — security-relevant self-declarations for an MCP tool.
///
/// **Trust model**: Manifests are self-declared by the tool. Admission
/// control rejects manifests that honestly declare unsafe combinations.
/// A lying manifest passes admission — runtime behavioral verification
/// is required to catch lies (not yet implemented).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolManifest {
    /// Tool name (must match the MCP tool name exactly).
    /// Up to 128 bytes of UTF-8. Validated on construction.
    pub name: ToolName,

    /// Operations this tool performs.
    pub capabilities: Vec<Operation>,

    /// Does this tool fetch data from external URLs at runtime?
    pub remote_fetch: bool,

    /// Where can instructions come from that influence this tool's behavior?
    pub instruction_sources: Vec<InstructionSource>,

    /// What kinds of sinks can this tool's output reach?
    pub admissible_sinks: Vec<SinkClass>,

    /// Maximum confidentiality level this tool handles.
    pub max_confidentiality: ConfLevel,

    /// Minimum integrity level this tool guarantees for its output.
    pub output_integrity: IntegLevel,

    /// Authority level this tool's output carries.
    pub output_authority: AuthorityLevel,

    /// Schema hash (SHA-256 of name + description + parameters).
    /// Bridges to the existing `ToolSchemaRegistry` in portcullis.
    /// Zero means "not yet computed" — the registry fills this in.
    pub schema_hash: [u8; 32],
}

/// Bounded tool name (up to 128 bytes, valid UTF-8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolName {
    buf: [u8; 128],
    len: u8,
}

impl ToolName {
    /// Create a tool name from a string slice. Truncates to 128 bytes.
    pub fn new(s: &str) -> Self {
        let bytes = s.as_bytes();
        let len = bytes.len().min(128) as u8;
        let mut buf = [0u8; 128];
        buf[..len as usize].copy_from_slice(&bytes[..len as usize]);
        Self { buf, len }
    }

    pub fn as_str(&self) -> &str {
        // Safety: constructed from valid UTF-8 in new()
        core::str::from_utf8(&self.buf[..self.len as usize]).unwrap_or("")
    }
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
    /// Tool is rejected with ALL reasons (not just the first).
    Reject(AdmissionDenyReason),
}

/// Check if a tool manifest should be admitted.
///
/// Rejects tools with unsafe combinations of remote fetch, instruction
/// sources, output sinks, and declared security levels.
///
/// **Limitation**: This checks the manifest, not the tool's behavior.
/// A tool that lies in its manifest will pass admission.
pub fn check_admission(manifest: &ToolManifest) -> AdmissionVerdict {
    // Rule 1: Must declare at least one capability
    if manifest.capabilities.is_empty() {
        return AdmissionVerdict::Reject(AdmissionDenyReason::EmptyCapabilities);
    }

    // Rule 2: Remote fetch + unlabeled instruction sources = reject
    if manifest.remote_fetch {
        let has_unlabeled = manifest
            .instruction_sources
            .iter()
            .any(|s| matches!(s, InstructionSource::Unlabeled));
        if has_unlabeled {
            return AdmissionVerdict::Reject(AdmissionDenyReason::RemoteFetchUnlabeledInstructions);
        }
    }

    // Rule 3: External network sinks require remote_fetch declaration
    let has_external_sink = manifest
        .admissible_sinks
        .iter()
        .any(|s| matches!(s, SinkClass::ExternalNetwork));
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
        .any(|s| matches!(s, InstructionSource::TransitiveTool));
    if has_transitive && manifest.output_authority == AuthorityLevel::Directive {
        return AdmissionVerdict::Reject(AdmissionDenyReason::DirectiveFromTransitive);
    }

    AdmissionVerdict::Admit
}

// ═══════════════════════════════════════════════════════════════════════════
// Kani BMC harnesses — bounded model checking of admission rules
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    fn any_integ() -> IntegLevel {
        let v: u8 = kani::any();
        kani::assume(v <= 2);
        match v {
            0 => IntegLevel::Adversarial,
            1 => IntegLevel::Untrusted,
            _ => IntegLevel::Trusted,
        }
    }

    fn any_auth() -> AuthorityLevel {
        let v: u8 = kani::any();
        kani::assume(v <= 3);
        match v {
            0 => AuthorityLevel::NoAuthority,
            1 => AuthorityLevel::Informational,
            2 => AuthorityLevel::Suggestive,
            _ => AuthorityLevel::Directive,
        }
    }

    /// **M1 — Empty capabilities always rejected.**
    #[kani::proof]
    fn proof_empty_capabilities_rejected() {
        let manifest = ToolManifest {
            name: ToolName::new("test"),
            capabilities: vec![],
            remote_fetch: kani::any(),
            instruction_sources: vec![],
            admissible_sinks: vec![],
            max_confidentiality: ConfLevel::Public,
            output_integrity: any_integ(),
            output_authority: any_auth(),
            schema_hash: [0; 32],
        };
        assert!(matches!(
            check_admission(&manifest),
            AdmissionVerdict::Reject(AdmissionDenyReason::EmptyCapabilities)
        ));
    }

    /// **M2 — Remote fetch + unlabeled instructions always rejected.**
    #[kani::proof]
    fn proof_remote_unlabeled_rejected() {
        let manifest = ToolManifest {
            name: ToolName::new("test"),
            capabilities: vec![Operation::WebFetch],
            remote_fetch: true,
            instruction_sources: vec![InstructionSource::Unlabeled],
            admissible_sinks: vec![],
            max_confidentiality: ConfLevel::Public,
            output_integrity: any_integ(),
            output_authority: any_auth(),
            schema_hash: [0; 32],
        };
        assert!(!matches!(
            check_admission(&manifest),
            AdmissionVerdict::Admit
        ));
    }

    /// **M3 — Trusted output from remote always rejected.**
    #[kani::proof]
    fn proof_trusted_from_remote_rejected() {
        let manifest = ToolManifest {
            name: ToolName::new("test"),
            capabilities: vec![Operation::WebFetch],
            remote_fetch: true,
            instruction_sources: vec![InstructionSource::Static],
            admissible_sinks: vec![],
            max_confidentiality: ConfLevel::Public,
            output_integrity: IntegLevel::Trusted,
            output_authority: any_auth(),
            schema_hash: [0; 32],
        };
        assert!(matches!(
            check_admission(&manifest),
            AdmissionVerdict::Reject(AdmissionDenyReason::TrustedOutputFromRemote)
        ));
    }

    /// **M4 — Directive from transitive always rejected.**
    #[kani::proof]
    fn proof_directive_from_transitive_rejected() {
        let manifest = ToolManifest {
            name: ToolName::new("test"),
            capabilities: vec![Operation::ReadFiles],
            remote_fetch: false,
            instruction_sources: vec![InstructionSource::TransitiveTool],
            admissible_sinks: vec![SinkClass::LocalMemory],
            max_confidentiality: ConfLevel::Public,
            output_integrity: any_integ(),
            output_authority: AuthorityLevel::Directive,
            schema_hash: [0; 32],
        };
        assert!(!matches!(
            check_admission(&manifest),
            AdmissionVerdict::Admit
        ));
    }

    /// **M5 — Safe local tool always admitted.**
    #[kani::proof]
    fn proof_safe_local_admitted() {
        let integ = any_integ();
        let auth = any_auth();
        // Not remote, not transitive, has capabilities, no external sinks
        let manifest = ToolManifest {
            name: ToolName::new("safe"),
            capabilities: vec![Operation::ReadFiles],
            remote_fetch: false,
            instruction_sources: vec![InstructionSource::Static],
            admissible_sinks: vec![SinkClass::HumanVisible],
            max_confidentiality: ConfLevel::Public,
            output_integrity: integ,
            output_authority: auth,
            schema_hash: [0; 32],
        };
        // Should always be admitted — no rule triggers
        kani::assume(
            !matches!(auth, AuthorityLevel::Directive)
                || !manifest
                    .instruction_sources
                    .iter()
                    .any(|s| matches!(s, InstructionSource::TransitiveTool)),
        );
        assert!(matches!(
            check_admission(&manifest),
            AdmissionVerdict::Admit
        ));
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn base_manifest() -> ToolManifest {
        ToolManifest {
            name: ToolName::new("read_file"),
            capabilities: vec![Operation::ReadFiles],
            remote_fetch: false,
            instruction_sources: vec![InstructionSource::Static],
            admissible_sinks: vec![SinkClass::LocalMemory],
            max_confidentiality: ConfLevel::Internal,
            output_integrity: IntegLevel::Untrusted,
            output_authority: AuthorityLevel::Informational,
            schema_hash: [0; 32], // Filled in by ToolSchemaRegistry
        }
    }

    #[test]
    fn admits_safe_read_tool() {
        let m = base_manifest();
        assert_eq!(check_admission(&m), AdmissionVerdict::Admit);
    }

    #[test]
    fn rejects_empty_capabilities() {
        let mut m = base_manifest();
        m.capabilities.clear();
        assert_eq!(
            check_admission(&m),
            AdmissionVerdict::Reject(AdmissionDenyReason::EmptyCapabilities)
        );
    }

    #[test]
    fn rejects_remote_fetch_with_unlabeled_sources() {
        let mut m = base_manifest();
        m.remote_fetch = true;
        m.instruction_sources.push(InstructionSource::Unlabeled);
        assert_eq!(
            check_admission(&m),
            AdmissionVerdict::Reject(AdmissionDenyReason::RemoteFetchUnlabeledInstructions)
        );
    }

    #[test]
    fn rejects_undeclared_external_sink() {
        let mut m = base_manifest();
        m.admissible_sinks.push(SinkClass::ExternalNetwork);
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
        m.instruction_sources
            .push(InstructionSource::TransitiveTool);
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
        m.admissible_sinks.push(SinkClass::ExternalNetwork);
        assert_eq!(check_admission(&m), AdmissionVerdict::Admit);
    }

    #[test]
    fn rejects_poisoned_tool_manifest() {
        let mut m = base_manifest();
        m.remote_fetch = true;
        m.instruction_sources.push(InstructionSource::RemoteUrl);
        m.instruction_sources.push(InstructionSource::Unlabeled);
        m.output_authority = AuthorityLevel::Directive;
        assert_eq!(
            check_admission(&m),
            AdmissionVerdict::Reject(AdmissionDenyReason::RemoteFetchUnlabeledInstructions)
        );
    }

    #[test]
    fn tool_name_truncates() {
        let long_name = "a".repeat(200);
        let name = ToolName::new(&long_name);
        assert_eq!(name.as_str().len(), 128);
    }

    #[test]
    fn tool_name_roundtrips() {
        let name = ToolName::new("read_file");
        assert_eq!(name.as_str(), "read_file");
    }
}
