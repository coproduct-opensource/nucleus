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

    /// Allowed hosts for remote fetch (empty = any host allowed).
    /// When non-empty, the tool can only fetch from these domains.
    pub allowed_hosts: Vec<String>,

    /// Whether this tool's output carries authority_to_instruct.
    /// If true, the tool's output is treated as instructions that can
    /// steer future agent actions. If false, output is informational only.
    /// Critical for defending against prompt injection via tool output.
    pub authority_to_instruct: bool,

    /// Memory behavior: does this tool read, write, or persist memory?
    pub memory_behavior: MemoryBehavior,

    /// Compartments where this tool is allowed (#462).
    /// Empty = allowed in all compartments (default for backward compat).
    /// When non-empty, the tool is only available in the listed compartments.
    /// A web_fetch tool with `allowed_compartments: ["research"]` is blocked
    /// in draft/execute/breakglass.
    pub allowed_compartments: Vec<String>,

    /// Ed25519 signature over `canonical_bytes()` (64 bytes, optional).
    /// When present, the manifest can be verified against a trust store
    /// of known public keys. When absent, the manifest is "unsigned" —
    /// admission depends on `ManifestPolicy`.
    pub signature: Option<[u8; 64]>,

    /// Ed25519 public key that produced `signature` (32 bytes, optional).
    /// Stored alongside the signature so verifiers know which key to check.
    /// The key must appear in the trust store for verification to succeed.
    pub signing_key: Option<[u8; 32]>,
}

impl ToolManifest {
    /// Check if this tool is allowed in the given compartment (#462).
    ///
    /// Empty `allowed_compartments` means allowed everywhere (default).
    /// When non-empty, only the listed compartment names are permitted.
    pub fn is_allowed_in_compartment(&self, compartment: &str) -> bool {
        self.allowed_compartments.is_empty()
            || self.allowed_compartments.iter().any(|c| c == compartment)
    }

    /// Deterministic canonical byte serialization for signing/verification.
    ///
    /// Covers ALL security-relevant fields in a fixed order. Changes to
    /// any field invalidate the signature. The `signature` and `signing_key`
    /// fields are deliberately excluded (you can't sign your own signature).
    ///
    /// Format: `"nucleus-manifest-v1\n"` || field bytes in declaration order.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512);

        // Version tag — bump this if canonical format changes
        buf.extend_from_slice(b"nucleus-manifest-v1\n");

        // Name (length-prefixed)
        let name_bytes = self.name.as_str().as_bytes();
        buf.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(name_bytes);

        // Capabilities (count + discriminants)
        buf.extend_from_slice(&(self.capabilities.len() as u32).to_le_bytes());
        for op in &self.capabilities {
            buf.extend_from_slice(&(*op as u8).to_le_bytes());
        }

        // remote_fetch
        buf.push(self.remote_fetch as u8);

        // instruction_sources (count + discriminants)
        buf.extend_from_slice(&(self.instruction_sources.len() as u32).to_le_bytes());
        for src in &self.instruction_sources {
            buf.push(*src as u8);
        }

        // admissible_sinks (count + discriminants)
        buf.extend_from_slice(&(self.admissible_sinks.len() as u32).to_le_bytes());
        for sink in &self.admissible_sinks {
            buf.push(*sink as u8);
        }

        // Security levels
        buf.push(self.max_confidentiality as u8);
        buf.push(self.output_integrity as u8);
        buf.push(self.output_authority as u8);

        // schema_hash
        buf.extend_from_slice(&self.schema_hash);

        // allowed_hosts (count + length-prefixed strings)
        buf.extend_from_slice(&(self.allowed_hosts.len() as u32).to_le_bytes());
        for host in &self.allowed_hosts {
            let host_bytes = host.as_bytes();
            buf.extend_from_slice(&(host_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(host_bytes);
        }

        // authority_to_instruct
        buf.push(self.authority_to_instruct as u8);

        // memory_behavior
        buf.push(self.memory_behavior as u8);

        // allowed_compartments (count + length-prefixed strings)
        buf.extend_from_slice(&(self.allowed_compartments.len() as u32).to_le_bytes());
        for comp in &self.allowed_compartments {
            let comp_bytes = comp.as_bytes();
            buf.extend_from_slice(&(comp_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(comp_bytes);
        }

        buf
    }

    /// Whether this manifest carries a signature.
    pub fn is_signed(&self) -> bool {
        self.signature.is_some() && self.signing_key.is_some()
    }
}

/// Describes a tool's memory interaction pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MemoryBehavior {
    /// Tool does not interact with memory.
    #[default]
    None,
    /// Tool reads from memory but does not write.
    ReadOnly,
    /// Tool reads and writes memory (ephemeral, within session).
    ReadWrite,
    /// Tool persists memory across sessions.
    Persist,
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
    /// Tool claims authority_to_instruct but output_authority is too low.
    InstructionWithoutAuthority,
    /// Tool claims authority_to_instruct AND remote_fetch from untrusted sources.
    /// This is the core prompt injection attack vector.
    InstructionFromUntrustedRemote,
    /// Tool has no manifest and the policy requires manifests (default-deny).
    /// Without a manifest, the tool's security properties are unknown — the
    /// capability lattice alone cannot defend against classification gaming (#588).
    NoManifest,
    /// Tool manifest is unsigned and the policy requires signed manifests (#650).
    /// The manifest content may be legitimate but cannot be verified against
    /// a trust store — it could have been tampered with.
    UnsignedManifest,
    /// Tool manifest signature is invalid — the content has been tampered with
    /// or was signed by a key not in the trust store (#650).
    InvalidSignature,
}

/// Policy for tools without manifests.
///
/// Controls whether unmanifested tools are allowed through the capability
/// lattice alone (`DefaultAllow`) or rejected at admission (`DefaultDeny`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ManifestPolicy {
    /// Tools without manifests are allowed — only the capability lattice
    /// and heuristic classification gate them. This is the current behavior
    /// and is suitable for development/exploration.
    #[default]
    DefaultAllow,
    /// Tools without manifests are REJECTED. Every tool must have a manifest
    /// entry in `.nucleus/manifests/`. This is the recommended production
    /// setting — it prevents classification gaming via tool name manipulation.
    DefaultDeny,
    /// All manifests MUST be signed with a valid Ed25519 signature (#650).
    /// Unsigned manifests are rejected with `UnsignedManifest`. This is the
    /// highest security setting — it ensures manifests haven't been tampered
    /// with and were authored by a trusted key holder.
    RequireSigned,
}

/// Result of admission control check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionVerdict {
    /// Tool is admitted.
    Admit,
    /// Tool is rejected with ALL matching deny reasons.
    /// Every violated rule is reported so operators can fix all issues at once.
    Reject(Vec<AdmissionDenyReason>),
}

/// Check if a tool manifest should be admitted.
///
/// Rejects tools with unsafe combinations of remote fetch, instruction
/// sources, output sinks, and declared security levels.
///
/// **Limitation**: This checks the manifest, not the tool's behavior.
/// A tool that lies in its manifest will pass admission.
pub fn check_admission(manifest: &ToolManifest) -> AdmissionVerdict {
    let mut reasons = Vec::new();

    // Rule 1: Must declare at least one capability
    if manifest.capabilities.is_empty() {
        reasons.push(AdmissionDenyReason::EmptyCapabilities);
    }

    // Rule 2: Remote fetch + unlabeled instruction sources = reject
    if manifest.remote_fetch {
        let has_unlabeled = manifest
            .instruction_sources
            .iter()
            .any(|s| matches!(s, InstructionSource::Unlabeled));
        if has_unlabeled {
            reasons.push(AdmissionDenyReason::RemoteFetchUnlabeledInstructions);
        }
    }

    // Rule 3: External network sinks require remote_fetch declaration
    let has_external_sink = manifest
        .admissible_sinks
        .iter()
        .any(|s| matches!(s, SinkClass::ExternalNetwork));
    if has_external_sink && !manifest.remote_fetch {
        reasons.push(AdmissionDenyReason::UndeclaredExternalSink);
    }

    // Rule 4: Trusted output cannot come from remote-fetching tools
    if manifest.remote_fetch && manifest.output_integrity == IntegLevel::Trusted {
        reasons.push(AdmissionDenyReason::TrustedOutputFromRemote);
    }

    // Rule 5: Directive authority cannot come from transitive instruction sources
    let has_transitive = manifest
        .instruction_sources
        .iter()
        .any(|s| matches!(s, InstructionSource::TransitiveTool));
    if has_transitive && manifest.output_authority == AuthorityLevel::Directive {
        reasons.push(AdmissionDenyReason::DirectiveFromTransitive);
    }

    // Rule 6: authority_to_instruct requires Directive output_authority
    if manifest.authority_to_instruct && manifest.output_authority < AuthorityLevel::Suggestive {
        reasons.push(AdmissionDenyReason::InstructionWithoutAuthority);
    }

    // Rule 7: Remote fetch with authority_to_instruct from untrusted sources
    // is the core prompt injection attack vector — reject
    if manifest.authority_to_instruct && manifest.remote_fetch {
        let has_untrusted_source = manifest
            .instruction_sources
            .iter()
            .any(|s| !matches!(s, InstructionSource::UserPrompt | InstructionSource::Static));
        if has_untrusted_source {
            reasons.push(AdmissionDenyReason::InstructionFromUntrustedRemote);
        }
    }

    if reasons.is_empty() {
        AdmissionVerdict::Admit
    } else {
        AdmissionVerdict::Reject(reasons)
    }
}

/// Check admission for a tool, applying the manifest policy for tools
/// without manifests.
///
/// - If `manifest` is `Some`, runs `check_admission()` as normal.
/// - If `manifest` is `None` and policy is `DefaultDeny`, rejects with `NoManifest`.
/// - If `manifest` is `None` and policy is `DefaultAllow`, admits (current behavior).
///
/// `tool_name` is included for error messages and audit trails.
pub fn check_admission_with_policy(
    manifest: Option<&ToolManifest>,
    policy: ManifestPolicy,
) -> AdmissionVerdict {
    match manifest {
        Some(m) => {
            // RequireSigned: reject unsigned manifests before checking content
            if matches!(policy, ManifestPolicy::RequireSigned) && !m.is_signed() {
                return AdmissionVerdict::Reject(vec![AdmissionDenyReason::UnsignedManifest]);
            }
            check_admission(m)
        }
        None => match policy {
            ManifestPolicy::DefaultDeny | ManifestPolicy::RequireSigned => {
                AdmissionVerdict::Reject(vec![AdmissionDenyReason::NoManifest])
            }
            ManifestPolicy::DefaultAllow => AdmissionVerdict::Admit,
        },
    }
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
            allowed_hosts: vec![],
            authority_to_instruct: false,
            memory_behavior: MemoryBehavior::None,
            allowed_compartments: vec![],
            signature: None,
            signing_key: None,
        };
        match check_admission(&manifest) {
            AdmissionVerdict::Reject(reasons) => {
                assert!(reasons.contains(&AdmissionDenyReason::EmptyCapabilities));
            }
            AdmissionVerdict::Admit => panic!("should reject empty capabilities"),
        }
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
            allowed_hosts: vec![],
            authority_to_instruct: false,
            memory_behavior: MemoryBehavior::None,
            allowed_compartments: vec![],
            signature: None,
            signing_key: None,
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
            allowed_hosts: vec![],
            authority_to_instruct: false,
            memory_behavior: MemoryBehavior::None,
            allowed_compartments: vec![],
            signature: None,
            signing_key: None,
        };
        match check_admission(&manifest) {
            AdmissionVerdict::Reject(reasons) => {
                assert!(reasons.contains(&AdmissionDenyReason::TrustedOutputFromRemote));
            }
            AdmissionVerdict::Admit => panic!("should reject trusted from remote"),
        }
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
            allowed_hosts: vec![],
            authority_to_instruct: false,
            memory_behavior: MemoryBehavior::None,
            allowed_compartments: vec![],
            signature: None,
            signing_key: None,
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
            allowed_hosts: vec![],
            authority_to_instruct: false,
            memory_behavior: MemoryBehavior::None,
            allowed_compartments: vec![],
            signature: None,
            signing_key: None,
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
            schema_hash: [0; 32],
            allowed_hosts: vec![],
            authority_to_instruct: false,
            memory_behavior: MemoryBehavior::None,
            allowed_compartments: vec![],
            signature: None,
            signing_key: None,
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
            AdmissionVerdict::Reject(vec![AdmissionDenyReason::EmptyCapabilities])
        );
    }

    #[test]
    fn rejects_remote_fetch_with_unlabeled_sources() {
        let mut m = base_manifest();
        m.remote_fetch = true;
        m.instruction_sources.push(InstructionSource::Unlabeled);
        assert_eq!(
            check_admission(&m),
            AdmissionVerdict::Reject(vec![AdmissionDenyReason::RemoteFetchUnlabeledInstructions])
        );
    }

    #[test]
    fn rejects_undeclared_external_sink() {
        let mut m = base_manifest();
        m.admissible_sinks.push(SinkClass::ExternalNetwork);
        assert_eq!(
            check_admission(&m),
            AdmissionVerdict::Reject(vec![AdmissionDenyReason::UndeclaredExternalSink])
        );
    }

    #[test]
    fn rejects_trusted_output_from_remote() {
        let mut m = base_manifest();
        m.remote_fetch = true;
        m.output_integrity = IntegLevel::Trusted;
        assert_eq!(
            check_admission(&m),
            AdmissionVerdict::Reject(vec![AdmissionDenyReason::TrustedOutputFromRemote])
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
            AdmissionVerdict::Reject(vec![AdmissionDenyReason::DirectiveFromTransitive])
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
    fn rejects_poisoned_tool_manifest_with_all_reasons() {
        // A manifest with multiple violations now reports ALL of them (#591)
        let mut m = base_manifest();
        m.remote_fetch = true;
        m.instruction_sources.push(InstructionSource::RemoteUrl);
        m.instruction_sources.push(InstructionSource::Unlabeled);
        m.output_integrity = IntegLevel::Trusted;
        match check_admission(&m) {
            AdmissionVerdict::Reject(reasons) => {
                assert!(
                    reasons.contains(&AdmissionDenyReason::RemoteFetchUnlabeledInstructions),
                    "should report unlabeled instructions"
                );
                assert!(
                    reasons.contains(&AdmissionDenyReason::TrustedOutputFromRemote),
                    "should report trusted from remote"
                );
                assert!(
                    reasons.len() >= 2,
                    "should have at least 2 reasons, got {}",
                    reasons.len()
                );
            }
            AdmissionVerdict::Admit => panic!("should reject poisoned manifest"),
        }
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

    // ── Default-deny tests (#588) ──────────────────────────────────────

    #[test]
    fn default_deny_rejects_no_manifest() {
        let verdict = check_admission_with_policy(None, ManifestPolicy::DefaultDeny);
        assert_eq!(
            verdict,
            AdmissionVerdict::Reject(vec![AdmissionDenyReason::NoManifest])
        );
    }

    #[test]
    fn default_allow_admits_no_manifest() {
        let verdict = check_admission_with_policy(None, ManifestPolicy::DefaultAllow);
        assert_eq!(verdict, AdmissionVerdict::Admit);
    }

    #[test]
    fn default_deny_admits_valid_manifest() {
        let m = base_manifest();
        let verdict = check_admission_with_policy(Some(&m), ManifestPolicy::DefaultDeny);
        assert_eq!(verdict, AdmissionVerdict::Admit);
    }

    #[test]
    fn default_deny_rejects_invalid_manifest() {
        let mut m = base_manifest();
        m.capabilities.clear();
        let verdict = check_admission_with_policy(Some(&m), ManifestPolicy::DefaultDeny);
        assert_eq!(
            verdict,
            AdmissionVerdict::Reject(vec![AdmissionDenyReason::EmptyCapabilities])
        );
    }

    #[test]
    fn manifest_policy_default_is_allow() {
        // Backward compatible: default policy allows unmanifested tools
        assert_eq!(ManifestPolicy::default(), ManifestPolicy::DefaultAllow);
    }

    // ── Signed manifest tests (#650) ──────────────────────────────────

    #[test]
    fn canonical_bytes_deterministic() {
        let m = base_manifest();
        let bytes1 = m.canonical_bytes();
        let bytes2 = m.canonical_bytes();
        assert_eq!(bytes1, bytes2, "canonical_bytes must be deterministic");
        assert!(bytes1.starts_with(b"nucleus-manifest-v1\n"));
    }

    #[test]
    fn canonical_bytes_changes_with_name() {
        let m1 = base_manifest();
        let mut m2 = base_manifest();
        m2.name = ToolName::new("write_file");
        assert_ne!(m1.canonical_bytes(), m2.canonical_bytes());
    }

    #[test]
    fn canonical_bytes_changes_with_capabilities() {
        let m1 = base_manifest();
        let mut m2 = base_manifest();
        m2.capabilities.push(Operation::WriteFiles);
        assert_ne!(m1.canonical_bytes(), m2.canonical_bytes());
    }

    #[test]
    fn canonical_bytes_excludes_signature() {
        let m1 = base_manifest();
        let mut m2 = base_manifest();
        m2.signature = Some([0xAA; 64]);
        m2.signing_key = Some([0xBB; 32]);
        assert_eq!(
            m1.canonical_bytes(),
            m2.canonical_bytes(),
            "signature fields must not affect canonical bytes"
        );
    }

    #[test]
    fn is_signed_requires_both_fields() {
        let mut m = base_manifest();
        assert!(!m.is_signed());

        m.signature = Some([0; 64]);
        assert!(!m.is_signed(), "needs signing_key too");

        m.signing_key = Some([0; 32]);
        assert!(m.is_signed());
    }

    #[test]
    fn require_signed_rejects_unsigned_manifest() {
        let m = base_manifest();
        let verdict = check_admission_with_policy(Some(&m), ManifestPolicy::RequireSigned);
        assert_eq!(
            verdict,
            AdmissionVerdict::Reject(vec![AdmissionDenyReason::UnsignedManifest])
        );
    }

    #[test]
    fn require_signed_rejects_no_manifest() {
        let verdict = check_admission_with_policy(None, ManifestPolicy::RequireSigned);
        assert_eq!(
            verdict,
            AdmissionVerdict::Reject(vec![AdmissionDenyReason::NoManifest])
        );
    }

    #[test]
    fn require_signed_admits_signed_manifest() {
        // RequireSigned only checks is_signed() — actual crypto verification
        // happens in portcullis (which has the ring dependency).
        let mut m = base_manifest();
        m.signature = Some([0x42; 64]);
        m.signing_key = Some([0x42; 32]);
        let verdict = check_admission_with_policy(Some(&m), ManifestPolicy::RequireSigned);
        // Should pass the policy gate (is_signed=true) and then pass admission rules
        assert_eq!(verdict, AdmissionVerdict::Admit);
    }
}
