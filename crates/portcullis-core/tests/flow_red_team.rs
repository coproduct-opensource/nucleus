//! Red-team test suite for the Flow Kernel.
//!
//! Each test encodes a concrete exploit family from real-world agent
//! vulnerabilities. Tests build causal chains of labeled flow nodes,
//! run them through `check_flow`, and assert the correct block with
//! a receipt showing the forbidden causal path.
//!
//! ## Exploit families tested
//!
//! 1. **Invariant (May 2025)**: public GitHub issue → private repo exfil via MCP
//! 2. **Unit 42 (Dec 2025)**: web page → memory poison → cross-session exfil
//! 3. **Tool-description poisoning**: MCP tool description injects instructions
//! 4. **Remote-skill instruction drift**: tool fetches instructions from URL at runtime
//! 5. **Localhost-origin confusion**: localhost data treated as trusted when it shouldn't be
//!
//! ## Honest status
//!
//! These tests exercise the pure flow checking functions. They do NOT
//! test integration with `Kernel::decide()` (not yet wired in).

use portcullis_core::flow::*;
use portcullis_core::receipt::*;
use portcullis_core::*;

fn node(id: NodeId, kind: NodeKind, label: IFCLabel, op: Option<Operation>) -> FlowNode {
    FlowNode {
        id,
        kind,
        label,
        parent_count: 0,
        parents: [0; MAX_PARENTS],
        operation: op,
    }
}

// ═════════════════════════════════════════════════════════════════════════
// Exploit 1: Invariant — public GitHub issue → private repo data exfil
//
// Attack: Attacker creates a public GitHub issue with hidden prompt
// injection. Agent reads the issue via MCP GitHub tool, then reads
// private repo files, then attempts to create a PR or comment
// containing the private data.
//
// Defense: The issue body gets label {Public, Adversarial, NoAuthority}.
// When combined with private repo data, authority stays NoAuthority.
// CreatePr requires Suggestive authority → BLOCKED.
// ═════════════════════════════════════════════════════════════════════════

#[test]
fn exploit_01_invariant_github_issue_exfil_via_pr() {
    let now = 1000;

    // Step 1: Agent reads malicious public GitHub issue
    let issue = node(1, NodeKind::WebContent, IFCLabel::web_content(now), None);

    // Step 2: Agent reads private repo file
    let private_file = node(
        2,
        NodeKind::FileRead,
        IFCLabel {
            confidentiality: ConfLevel::Internal,
            integrity: IntegLevel::Trusted,
            provenance: ProvenanceSet::SYSTEM,
            freshness: Freshness {
                observed_at: now,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::Directive,
        },
        None,
    );

    // Step 3: Agent plans to combine issue instructions with private data
    let plan_label = propagate_label(
        &[issue.label, private_file.label],
        intrinsic_label(NodeKind::ModelPlan, now),
    );
    let plan = node(3, NodeKind::ModelPlan, plan_label, None);

    // Step 4: Agent attempts to create PR with private data
    let action_label = propagate_label(
        &[plan.label],
        intrinsic_label(NodeKind::OutboundAction, now),
    );
    let action = node(
        4,
        NodeKind::OutboundAction,
        action_label,
        Some(Operation::CreatePr),
    );

    // BLOCKED: authority escalation
    let verdict = check_flow(&action, now + 1);
    assert_eq!(
        verdict,
        FlowVerdict::Deny(FlowDenyReason::AuthorityEscalation)
    );

    // Receipt shows the causal chain
    let receipt = build_receipt(&action, &[&issue, &private_file, &plan], verdict, now + 1);
    assert_eq!(receipt.ancestors().len(), 3);
    assert!(receipt.display_chain().contains("BLOCKED"));
    assert!(receipt.display_chain().contains("authority"));
}

#[test]
fn exploit_01b_invariant_exfil_via_git_push() {
    let now = 1000;
    let issue = node(1, NodeKind::WebContent, IFCLabel::web_content(now), None);
    let private_file = node(
        2,
        NodeKind::FileRead,
        IFCLabel {
            confidentiality: ConfLevel::Internal,
            integrity: IntegLevel::Trusted,
            provenance: ProvenanceSet::SYSTEM,
            freshness: Freshness {
                observed_at: now,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::Directive,
        },
        None,
    );
    let combined = propagate_label(
        &[issue.label, private_file.label],
        intrinsic_label(NodeKind::OutboundAction, now),
    );
    let push = node(
        3,
        NodeKind::OutboundAction,
        combined,
        Some(Operation::GitPush),
    );

    // BLOCKED: authority escalation (NoAuthority < Suggestive)
    assert_eq!(
        check_flow(&push, now + 1),
        FlowVerdict::Deny(FlowDenyReason::AuthorityEscalation)
    );
}

// ═════════════════════════════════════════════════════════════════════════
// Exploit 2: Unit 42 — web page → memory poison → cross-session exfil
//
// Attack: Malicious web page contains hidden instructions. Agent reads
// the page, writes a summary to memory. In a LATER session, the memory
// entry is read and its instructions cause the agent to exfiltrate
// conversation history.
//
// Defense: Web content label propagates through memory write/read.
// The memory entry inherits {Adversarial, NoAuthority}. When the
// later session tries to exfil, both authority and integrity checks fire.
// ═════════════════════════════════════════════════════════════════════════

#[test]
fn exploit_02_unit42_memory_poisoning_cross_session() {
    let session1_time = 1000;
    let session2_time = session1_time + 86400; // Next day

    // Session 1: Agent reads malicious web page
    let web_page = node(
        1,
        NodeKind::WebContent,
        IFCLabel::web_content(session1_time),
        None,
    );

    // Session 1: Agent writes "summary" to memory (tainted by web content)
    let memory_write_label = propagate_label(
        &[web_page.label],
        intrinsic_label(NodeKind::MemoryWrite, session1_time),
    );
    assert_eq!(memory_write_label.integrity, IntegLevel::Adversarial);
    assert_eq!(memory_write_label.authority, AuthorityLevel::NoAuthority);

    // Session 2: Agent reads the tainted memory entry
    let memory_read_label = propagate_label(
        &[memory_write_label],
        intrinsic_label(NodeKind::MemoryRead, session2_time),
    );

    // Memory entry is STILL adversarial and has no authority
    assert_eq!(memory_read_label.integrity, IntegLevel::Adversarial);
    assert_eq!(memory_read_label.authority, AuthorityLevel::NoAuthority);

    // Session 2: Agent reads user's conversation (trusted, private)
    let conversation = node(
        10,
        NodeKind::UserPrompt,
        IFCLabel::user_prompt(session2_time),
        None,
    );

    // Session 2: Agent tries to exfiltrate via git push
    let exfil_label = propagate_label(
        &[memory_read_label, conversation.label],
        intrinsic_label(NodeKind::OutboundAction, session2_time),
    );
    let exfil = node(
        11,
        NodeKind::OutboundAction,
        exfil_label,
        Some(Operation::GitPush),
    );

    // BLOCKED: authority escalation (memory taint → NoAuthority)
    let verdict = check_flow(&exfil, session2_time + 1);
    assert!(matches!(verdict, FlowVerdict::Deny(_)));

    let receipt = build_receipt(
        &exfil,
        &[&web_page, &conversation],
        verdict,
        session2_time + 1,
    );
    assert!(receipt.display_chain().contains("BLOCKED"));
}

// ═════════════════════════════════════════════════════════════════════════
// Exploit 3: Tool-description poisoning
//
// Attack: MCP tool description contains hidden prompt injection.
// The agent reads the tool description (which has instructions embedded
// in it) and follows those instructions to exfiltrate data.
//
// Defense: Tool descriptions get {Untrusted, Informational} label.
// They cannot steer privileged actions (Suggestive authority required
// for writes/exfil).
// ═════════════════════════════════════════════════════════════════════════

#[test]
fn exploit_03_tool_description_poisoning() {
    let now = 1000;

    // Tool description with hidden injection
    let tool_desc = node(
        1,
        NodeKind::ToolResponse,
        IFCLabel::tool_response(now),
        None,
    );

    // Tool description has Informational authority (can inform, not direct)
    assert_eq!(tool_desc.label.authority, AuthorityLevel::Informational);

    // Agent combines tool description with its plan
    let plan_label = propagate_label(
        &[tool_desc.label],
        intrinsic_label(NodeKind::ModelPlan, now),
    );

    // Plan inherits Informational authority (min of Directive, Informational)
    assert_eq!(plan_label.authority, AuthorityLevel::Informational);

    // Agent tries to run a shell command based on the tool description
    let action_label = propagate_label(
        &[plan_label],
        intrinsic_label(NodeKind::OutboundAction, now),
    );
    let bash = node(
        3,
        NodeKind::OutboundAction,
        action_label,
        Some(Operation::RunBash),
    );

    // BLOCKED: RunBash requires Suggestive, tool desc only gives Informational
    assert_eq!(
        check_flow(&bash, now + 1),
        FlowVerdict::Deny(FlowDenyReason::AuthorityEscalation)
    );
}

// ═════════════════════════════════════════════════════════════════════════
// Exploit 4: Remote-skill instruction drift
//
// Attack: An MCP tool fetches instructions from a remote URL at runtime.
// The URL content changes after initial approval, injecting new
// malicious instructions.
//
// Defense: Remote URL content gets {Public, Adversarial, NoAuthority}.
// Even if the tool wraps it, propagation preserves the taint.
// ═════════════════════════════════════════════════════════════════════════

#[test]
fn exploit_04_remote_instruction_drift() {
    let now = 1000;

    // Tool fetches instructions from a remote URL
    let remote_instructions = node(1, NodeKind::WebContent, IFCLabel::web_content(now), None);

    // Tool processes the remote instructions and produces output
    let tool_output_label = propagate_label(
        &[remote_instructions.label],
        intrinsic_label(NodeKind::ToolResponse, now),
    );

    // Output inherits adversarial integrity and no authority
    assert_eq!(tool_output_label.integrity, IntegLevel::Adversarial);
    assert_eq!(tool_output_label.authority, AuthorityLevel::NoAuthority);

    // Agent tries to write files based on the tool output
    let action_label = propagate_label(
        &[tool_output_label],
        intrinsic_label(NodeKind::OutboundAction, now),
    );
    let write = node(
        3,
        NodeKind::OutboundAction,
        action_label,
        Some(Operation::WriteFiles),
    );

    // BLOCKED: authority escalation (NoAuthority < Suggestive)
    assert_eq!(
        check_flow(&write, now + 1),
        FlowVerdict::Deny(FlowDenyReason::AuthorityEscalation)
    );
}

// ═════════════════════════════════════════════════════════════════════════
// Exploit 5: Localhost-origin confusion
//
// Attack: Agent reads from a localhost service (e.g., http://localhost:8080)
// and treats the data as trusted because it's "local." But the localhost
// service could be compromised, serving attacker-controlled content.
//
// Defense: Localhost content is labeled as ToolResponse (Untrusted
// integrity) not as System (Trusted). The untrusted label prevents
// it from reaching integrity-gated sinks.
// ═════════════════════════════════════════════════════════════════════════

#[test]
fn exploit_05_localhost_origin_confusion() {
    let now = 1000;

    // Agent reads from localhost service (labeled as tool response, not system)
    let localhost_data = node(
        1,
        NodeKind::ToolResponse,
        IFCLabel::tool_response(now),
        None,
    );

    // Localhost data is Untrusted (not Trusted like system files)
    assert_eq!(localhost_data.label.integrity, IntegLevel::Untrusted);

    // Agent tries to git push using data from localhost
    let action_label = propagate_label(
        &[localhost_data.label],
        intrinsic_label(NodeKind::OutboundAction, now),
    );
    let push = node(
        2,
        NodeKind::OutboundAction,
        action_label,
        Some(Operation::GitPush),
    );

    // BLOCKED: authority escalation fires first (Informational < Suggestive for GitPush).
    // If authority were sufficient, integrity would also block (Untrusted < Trusted).
    assert!(matches!(check_flow(&push, now + 1), FlowVerdict::Deny(_)));
}

// ═════════════════════════════════════════════════════════════════════════
// Positive tests: legitimate flows that SHOULD be allowed
// ═════════════════════════════════════════════════════════════════════════

#[test]
fn legitimate_user_writes_file() {
    let now = 1000;
    let user = node(1, NodeKind::UserPrompt, IFCLabel::user_prompt(now), None);
    let action_label = propagate_label(
        &[user.label],
        intrinsic_label(NodeKind::OutboundAction, now),
    );
    let write = node(
        2,
        NodeKind::OutboundAction,
        action_label,
        Some(Operation::WriteFiles),
    );
    assert_eq!(check_flow(&write, now + 1), FlowVerdict::Allow);
}

#[test]
fn legitimate_user_reads_web() {
    let now = 1000;
    let user = node(1, NodeKind::UserPrompt, IFCLabel::user_prompt(now), None);
    let action_label = propagate_label(
        &[user.label],
        intrinsic_label(NodeKind::OutboundAction, now),
    );
    let search = node(
        2,
        NodeKind::OutboundAction,
        action_label,
        Some(Operation::WebSearch),
    );
    assert_eq!(check_flow(&search, now + 1), FlowVerdict::Allow);
}

#[test]
fn legitimate_user_creates_pr_from_own_work() {
    let now = 1000;
    let user = node(1, NodeKind::UserPrompt, IFCLabel::user_prompt(now), None);
    let file = node(
        2,
        NodeKind::FileRead,
        IFCLabel {
            confidentiality: ConfLevel::Internal,
            integrity: IntegLevel::Trusted,
            provenance: ProvenanceSet::SYSTEM,
            freshness: Freshness {
                observed_at: now,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::Directive,
        },
        None,
    );
    let plan_label = propagate_label(
        &[user.label, file.label],
        intrinsic_label(NodeKind::ModelPlan, now),
    );
    let action_label = propagate_label(
        &[plan_label],
        intrinsic_label(NodeKind::OutboundAction, now),
    );
    let pr = node(
        4,
        NodeKind::OutboundAction,
        action_label,
        Some(Operation::CreatePr),
    );

    // ALLOWED: user-directed, trusted data, no web taint
    assert_eq!(check_flow(&pr, now + 1), FlowVerdict::Allow);
}
